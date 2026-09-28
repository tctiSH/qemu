/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
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
#include "qemu/cutils.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "system/cpus.h"
#include "qemu/main-loop.h"
#include "qemu/option.h"
#include "qemu/seqlock.h"
#include "system/replay.h"
#include "system/runstate.h"
#include "hw/core/cpu.h"
#include "system/cpu-timers.h"
#include "system/cpu-timers-internal.h"
#include "exec/icount.h"

/* clock and ticks */

static int64_t cpu_get_ticks_locked(void)
{
    int64_t ticks = timers_state.cpu_ticks_offset;
    if (timers_state.cpu_ticks_enabled) {
        ticks += cpu_get_host_ticks();
    }

    if (timers_state.cpu_ticks_prev > ticks) {
        /* Non increasing ticks may happen if the host uses software suspend. */
        timers_state.cpu_ticks_offset += timers_state.cpu_ticks_prev - ticks;
        ticks = timers_state.cpu_ticks_prev;
    }

    timers_state.cpu_ticks_prev = ticks;
    return ticks;
}

/*
 * return the time elapsed in VM between vm_start and vm_stop.
 * cpu_get_ticks() uses units of the host CPU cycle counter.
 */
int64_t cpu_get_ticks(void)
{
    int64_t ticks;

    qemu_spin_lock(&timers_state.vm_clock_lock);
    ticks = cpu_get_ticks_locked();
    qemu_spin_unlock(&timers_state.vm_clock_lock);
    return ticks;
}

int64_t cpu_get_clock_locked(void)
{
    int64_t time;

    time = timers_state.cpu_clock_offset;
    if (timers_state.cpu_ticks_enabled) {
        time += get_clock();
    }

    return time;
}

/*
 * Return the monotonic time elapsed in VM, i.e.,
 * the time between vm_start and vm_stop
 */
int64_t cpu_get_clock(void)
{
    int64_t ti;
    unsigned start;

    do {
        start = seqlock_read_begin(&timers_state.vm_clock_seqlock);
        ti = cpu_get_clock_locked();
    } while (seqlock_read_retry(&timers_state.vm_clock_seqlock, start));

    return ti;
}

/*
 * tctiSH: a stopped VM's clock stands still. That's what QEMU means by
 * stopping it, and it's no use to us: the VM stops for every snapshot save,
 * for parking, and a snapshot load puts the clock back to wherever the
 * snapshot was taken. Each time, the guest comes back behind by however long
 * it was away, and nothing in it notices: Linux keeps time from the TSC and
 * only reads the RTC at boot. Resuming a session iOS had killed left the guest
 * behind by however long the app was dead.
 *
 * A process that iOS merely suspends has none of this, because its clock
 * never stops, and on return the guest sees the TSC jump and catches up by
 * itself. So make every stop look like a suspend. Remember the host time the
 * clock stopped at, and when it starts again, move it on by everything since.
 * After a snapshot load, the moment to count from is when the snapshot was
 * taken; see tctish_clock_loaded.
 *
 * Host monotonic nanoseconds, from get_clock(), valid only while
 * tctish_stopped is set. It can be negative: after a load it is counted back
 * from now by the snapshot's age, and get_clock() starts near zero when the
 * host boots, so a snapshot older than the host's uptime lands before it.
 * Measured on device: a negative value used as "nothing to catch up" left a
 * three-day-old session three days behind.
 */
static int64_t tctish_stopped_at;
static bool tctish_stopped;

/* tctiSH: a sample of both host counters at start-up; see tctish_host_ticks_for. */
static int64_t tctish_clock_origin;
static int64_t tctish_ticks_origin;

/*
 * tctiSH: host ticks in @ns nanoseconds. The VM's clock is kept in both, and
 * on hosts without a cycle counter QEMU's host ticks *are* get_clock(), so the
 * ratio is 1. That includes arm64, and so every host tctiSH runs on. It's
 * measured rather than assumed, so a host with a real cycle counter gets it
 * right too.
 */
static int64_t tctish_host_ticks_for(int64_t ns)
{
    int64_t clock = get_clock() - tctish_clock_origin;
    int64_t ticks = cpu_get_host_ticks() - tctish_ticks_origin;

    if (clock < NANOSECONDS_PER_SECOND || ticks <= 0) {
        return ns;
    }
    return (int64_t)((double)ns * ((double)ticks / (double)clock));
}

/* Call with vm_clock_seqlock held for writing, with the clock stopped. */
static void tctish_clock_catch_up_locked(void)
{
    int64_t elapsed;

    if (!tctish_stopped || icount_enabled()) {
        return;
    }

    elapsed = MAX(get_clock() - tctish_stopped_at, 0);
    timers_state.cpu_clock_offset += elapsed;
    timers_state.cpu_ticks_offset += tctish_host_ticks_for(elapsed);
    tctish_stopped = false;
}

/*
 * tctiSH: a snapshot taken at @taken (host wall clock, in nanoseconds since
 * the epoch) has just been loaded, clock and all. The clock now reads what it
 * read then, so the time to catch up is everything since, whenever and in
 * whichever process that was. A snapshot from the future (a host clock put
 * back) catches up by nothing rather than going backwards.
 */
void tctish_clock_loaded(int64_t taken)
{
    int64_t since = MAX(qemu_clock_get_ns(QEMU_CLOCK_HOST) - taken, 0);

    tctish_stopped_at = get_clock() - since;
    tctish_stopped = true;
}

/*
 * enable cpu_get_ticks()
 * Caller must hold BQL which serves as mutex for vm_clock_seqlock.
 */
void cpu_enable_ticks(void)
{
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (!timers_state.cpu_ticks_enabled) {
        tctish_clock_catch_up_locked();
        timers_state.cpu_ticks_offset -= cpu_get_host_ticks();
        timers_state.cpu_clock_offset -= get_clock();
        timers_state.cpu_ticks_enabled = 1;
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
}

/*
 * disable cpu_get_ticks() : the clock is stopped. You must not call
 * cpu_get_ticks() after that.
 * Caller must hold BQL which serves as mutex for vm_clock_seqlock.
 */
void cpu_disable_ticks(void)
{
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset += cpu_get_host_ticks();
        timers_state.cpu_clock_offset = cpu_get_clock_locked();
        timers_state.cpu_ticks_enabled = 0;
        tctish_stopped_at = get_clock();
        tctish_stopped = true;
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                         &timers_state.vm_clock_lock);
}

static bool icount_state_needed(void *opaque)
{
    return icount_enabled();
}

static bool warp_timer_state_needed(void *opaque)
{
    TimersState *s = opaque;
    return s->icount_warp_timer != NULL;
}

static bool adjust_timers_state_needed(void *opaque)
{
    TimersState *s = opaque;
    return s->icount_rt_timer != NULL;
}

static bool icount_shift_state_needed(void *opaque)
{
    return icount_enabled() == ICOUNT_ADAPTATIVE;
}

/*
 * Subsection for warp timer migration is optional, because may not be created
 */
static const VMStateDescription icount_vmstate_warp_timer = {
    .name = "timer/icount/warp_timer",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = warp_timer_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_INT64(vm_clock_warp_start, TimersState),
        VMSTATE_TIMER_PTR(icount_warp_timer, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription icount_vmstate_adjust_timers = {
    .name = "timer/icount/timers",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = adjust_timers_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_TIMER_PTR(icount_rt_timer, TimersState),
        VMSTATE_TIMER_PTR(icount_vm_timer, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription icount_vmstate_shift = {
    .name = "timer/icount/shift",
    .version_id = 2,
    .minimum_version_id = 2,
    .needed = icount_shift_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_INT16(icount_time_shift, TimersState),
        VMSTATE_INT64(last_delta, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

/*
 * This is a subsection for icount migration.
 */
static const VMStateDescription icount_vmstate_timers = {
    .name = "timer/icount",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = icount_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_INT64(qemu_icount_bias, TimersState),
        VMSTATE_INT64(qemu_icount, TimersState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &icount_vmstate_warp_timer,
        &icount_vmstate_adjust_timers,
        &icount_vmstate_shift,
        NULL
    }
};

static const VMStateDescription vmstate_timers = {
    .name = "timer",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_INT64(cpu_ticks_offset, TimersState),
        VMSTATE_UNUSED(8),
        VMSTATE_INT64_V(cpu_clock_offset, TimersState, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &icount_vmstate_timers,
        NULL
    }
};

static void do_nothing(CPUState *cpu, run_on_cpu_data unused)
{
}

void qemu_timer_notify_cb(void *opaque, QEMUClockType type)
{
    if (!icount_enabled() || type != QEMU_CLOCK_VIRTUAL) {
        qemu_notify_event();
        return;
    }

    if (qemu_in_vcpu_thread()) {
        /*
         * A CPU is currently running; send it out of the
         * tcg_cpu_exec() loop so it will recalculate its
         * icount deadline immediately.
         */
        cpu_exit(current_cpu);
    } else if (first_cpu) {
        /*
         * cpu_exit() is not enough to kick a halted CPU out of
         * qemu_tcg_wait_io_event.  async_run_on_cpu, instead,
         * causes cpu_thread_is_idle to return false.  This way,
         * handle_icount_deadline can run.
         * If we have no CPUs at all for some reason, we don't
         * need to do anything.
         */
        async_run_on_cpu(first_cpu, do_nothing, RUN_ON_CPU_NULL);
    }
}

TimersState timers_state;

/* initialize timers state and the cpu throttle for convenience */
void cpu_timers_init(void)
{
    tctish_clock_origin = get_clock();
    tctish_ticks_origin = cpu_get_host_ticks();

    seqlock_init(&timers_state.vm_clock_seqlock);
    qemu_spin_init(&timers_state.vm_clock_lock);
    vmstate_register(NULL, 0, &vmstate_timers, &timers_state);
}
