/*
 * QEMU TCG Multi Threaded vCPUs implementation
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2014 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "exec/cpu-common.h"
#include "system/tcg.h"
#include "system/replay.h"
#include "exec/icount.h"
#include "qemu/main-loop.h"
#include "qemu/notify.h"
#include "qemu/guest-random.h"
#include "hw/core/boards.h"
#include "accel/tcg/cpu-loop.h"
#include "tcg/startup.h"
#include "tcg-accel-ops.h"
#include "tcg-accel-ops-mttcg.h"

#ifdef CONFIG_DARWIN
#include <pthread/qos.h>
#endif

typedef struct MttcgForceRcuNotifier {
    Notifier notifier;
    CPUState *cpu;
} MttcgForceRcuNotifier;

static void do_nothing(CPUState *cpu, run_on_cpu_data d)
{
}

static void mttcg_force_rcu(Notifier *notify, void *data)
{
    CPUState *cpu = container_of(notify, MttcgForceRcuNotifier, notifier)->cpu;

    /*
     * Called with rcu_registry_lock held, using async_run_on_cpu() ensures
     * that there are no deadlocks.
     */
    async_run_on_cpu(cpu, do_nothing, RUN_ON_CPU_NULL);
}

#ifdef CONFIG_DARWIN
/*
 * The QoS class asked for, or QOS_CLASS_UNSPECIFIED for the one each thread
 * started in, and the bottom half that hands it to every vCPU. The vCPU list
 * is walked with the BQL held in the main loop, which the app's thread
 * cannot do itself.
 */
static int tctish_vcpu_qos = QOS_CLASS_UNSPECIFIED;
static QEMUBH *tctish_vcpu_qos_bh;

/*
 * The class this vCPU thread started in, whatever Darwin gave it at creation,
 * and whether it has been moved from it. QOS_CLASS_UNSPECIFIED, asked for,
 * puts a moved thread back and leaves any other alone, so that the default
 * changes nothing about how the vCPUs run. A thread that started with no class
 * can't be given none again (Darwin takes only real classes), so it goes back
 * to QOS_CLASS_DEFAULT, the nearest.
 */
static __thread qos_class_t tctish_vcpu_start_qos;
static __thread bool tctish_vcpu_start_qos_known;
static __thread bool tctish_vcpu_qos_moved;

static void tctish_vcpu_apply_qos(void)
{
    qos_class_t want = qatomic_read(&tctish_vcpu_qos);

    if (!tctish_vcpu_start_qos_known) {
        tctish_vcpu_start_qos = qos_class_self();
        tctish_vcpu_start_qos_known = true;
    }
    if (want == QOS_CLASS_UNSPECIFIED) {
        if (!tctish_vcpu_qos_moved) {
            return;
        }
        want = tctish_vcpu_start_qos != QOS_CLASS_UNSPECIFIED ?
               tctish_vcpu_start_qos : QOS_CLASS_DEFAULT;
    }

    if (qos_class_self() != want &&
        pthread_set_qos_class_self_np(want, 0) == 0) {
        tctish_vcpu_qos_moved = want != tctish_vcpu_start_qos;
    }
}

static void tctish_vcpu_qos_work(CPUState *cpu, run_on_cpu_data data)
{
    tctish_vcpu_apply_qos();
}

static void tctish_vcpu_qos_now(void *opaque)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        async_run_on_cpu(cpu, tctish_vcpu_qos_work, RUN_ON_CPU_NULL);
    }
}

bool tctish_vcpu_set_qos(int qos_class)
{
    QEMUBH *bh = qatomic_read(&tctish_vcpu_qos_bh);

    if (bh == NULL) {
        return false;
    }
    smp_mb_acquire();
    qatomic_set(&tctish_vcpu_qos, qos_class);
    qemu_bh_schedule(bh);
    return true;
}
#else
static void tctish_vcpu_apply_qos(void)
{
}

bool tctish_vcpu_set_qos(int qos_class)
{
    return false;
}
#endif

/*
 * In the multi-threaded case each vCPU has its own thread. The TLS
 * variable current_cpu can be used deep in the code to find the
 * current CPUState for a given thread.
 */

static void *mttcg_cpu_thread_fn(void *arg)
{
    MttcgForceRcuNotifier force_rcu;
    CPUState *cpu = arg;

    assert(tcg_enabled());
    g_assert(!icount_enabled());

    rcu_register_thread();
    force_rcu.notifier.notify = mttcg_force_rcu;
    force_rcu.cpu = cpu;
    rcu_add_force_rcu_notifier(&force_rcu.notifier);
    tcg_register_thread();
    tctish_vcpu_apply_qos();

    bql_lock();
    qemu_thread_get_self(cpu->thread);

    cpu->thread_id = qemu_get_thread_id();
    cpu->neg.can_do_io = true;
    current_cpu = cpu;
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        qemu_process_cpu_events(cpu);

        if (cpu_can_run(cpu)) {
            int r;
            bql_unlock();
            r = tcg_cpu_exec(cpu);
            bql_lock();
            switch (r) {
            case EXCP_DEBUG:
                cpu_handle_guest_debug(cpu);
                break;
            case EXCP_HALTED:
                /*
                 * Usually cpu->halted is set, but may have already been
                 * reset by another thread by the time we arrive here.
                 */
                break;
            case EXCP_ATOMIC:
                bql_unlock();
                cpu_exec_step_atomic(cpu);
                bql_lock();
            default:
                /* Ignore everything else? */
                break;
            }
        }
    } while (!cpu->unplug || cpu_can_run(cpu));

    /* Before the unplug can finish, so that a vCPU plugged next finds it. */
    tcg_unregister_thread();
    tcg_cpu_destroy(cpu);
    bql_unlock();
    rcu_remove_force_rcu_notifier(&force_rcu.notifier);
    rcu_unregister_thread();
    return NULL;
}

void mttcg_start_vcpu_thread(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    g_assert(tcg_enabled());
    tcg_cpu_init_cflags(cpu, current_machine->smp.max_cpus > 1);

#ifdef CONFIG_DARWIN
    /* Here, in the main loop, so that the bottom half belongs to it. */
    if (tctish_vcpu_qos_bh == NULL) {
        qatomic_store_release(&tctish_vcpu_qos_bh,
                              qemu_bh_new(tctish_vcpu_qos_now, NULL));
    }
#endif

    /* create a thread per vCPU with TCG (MTTCG) */
    snprintf(thread_name, VCPU_THREAD_NAME_SIZE, "CPU %d/TCG",
             cpu->cpu_index);

    qemu_thread_create(cpu->thread, thread_name, mttcg_cpu_thread_fn,
                       cpu, QEMU_THREAD_JOINABLE);
}
