/*
 * Virtio 9p backend
 *
 * Copyright IBM, Corp. 2010
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

/*
 * Not so fast! You might want to read the 9p developer docs first:
 * https://wiki.qemu.org/Documentation/9p
 */

#include "qemu/osdep.h"
#include "hw/virtio/virtio.h"
#include "qemu/sockets.h"
#include "virtio-9p.h"
#include "fsdev/qemu-fsdev.h"
#include "coth.h"
#include "hw/core/qdev-properties.h"
#include "hw/virtio/virtio-access.h"
#include "qapi/error.h"
#include "qemu/iov.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "system/qtest.h"
#include "migration/qemu-file-types.h"
#include "migration/vmstate.h"
#include "system/runstate.h"

static void coroutine_fn virtio_9p_push_and_notify(V9fsPDU *pdu)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];

    /* push onto queue and notify */
    virtqueue_push(v->vq, elem, pdu->size);
    g_free(elem);
    v->elems[pdu->idx] = NULL;

    /* FIXME: we should batch these completions */
    virtio_notify(VIRTIO_DEVICE(v), v->vq);
}

static void handle_9p_output(VirtIODevice *vdev, VirtQueue *vq)
{
    V9fsVirtioState *v = (V9fsVirtioState *)vdev;
    V9fsState *s = &v->state;
    V9fsPDU *pdu;
    ssize_t len;
    VirtQueueElement *elem;

    /* Left in the ring until the VM runs again; see virtio_9p_vm_change(). */
    if (v->stopped) {
        return;
    }

    while ((pdu = pdu_alloc(s))) {
        P9MsgHeader out;

        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            goto out_free_pdu;
        }

        if (iov_size(elem->in_sg, elem->in_num) < 7) {
            virtio_error(vdev,
                         "The guest sent a VirtFS request without space for "
                         "the reply");
            goto out_free_req;
        }

        len = iov_to_buf(elem->out_sg, elem->out_num, 0, &out, 7);
        if (len != 7) {
            virtio_error(vdev, "The guest sent a malformed VirtFS request: "
                         "header size is %zd, should be 7", len);
            goto out_free_req;
        }

        v->elems[pdu->idx] = elem;

        pdu_submit(pdu, &out);
    }

    return;

out_free_req:
    virtqueue_detach_element(vq, elem, 0);
    g_free(elem);
out_free_pdu:
    pdu_free(pdu);
}

static uint64_t virtio_9p_get_features(VirtIODevice *vdev, uint64_t features,
                                       Error **errp)
{
    virtio_add_feature(&features, VIRTIO_9P_MOUNT_TAG);
    return features;
}

static void virtio_9p_get_config(VirtIODevice *vdev, uint8_t *config)
{
    int len;
    struct virtio_9p_config *cfg;
    V9fsVirtioState *v = VIRTIO_9P(vdev);
    V9fsState *s = &v->state;

    len = strlen(s->tag);
    cfg = g_malloc0(sizeof(struct virtio_9p_config) + len);
    virtio_stw_p(vdev, &cfg->tag_len, len);
    /* We don't copy the terminating null to config space */
    memcpy(cfg->tag, s->tag, len);
    memcpy(config, cfg, v->config_size);
    g_free(cfg);
}

static void virtio_9p_drop_resubmit(V9fsVirtioState *v);

static void virtio_9p_reset(VirtIODevice *vdev)
{
    V9fsVirtioState *v = (V9fsVirtioState *)vdev;

    virtio_9p_drop_resubmit(v);
    v9fs_reset(&v->state);
}

static ssize_t coroutine_fn
virtio_pdu_vmarshal(V9fsPDU *pdu, size_t offset, const char *fmt, va_list ap)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];
    ssize_t ret;

    ret = v9fs_iov_vmarshal(elem->in_sg, elem->in_num, offset, 1, fmt, ap);
    if (ret < 0) {
        VirtIODevice *vdev = VIRTIO_DEVICE(v);

        virtio_error(vdev, "Failed to encode VirtFS reply type %d",
                     pdu->id + 1);
    }
    return ret;
}

static ssize_t coroutine_fn
virtio_pdu_vunmarshal(V9fsPDU *pdu, size_t offset, const char *fmt, va_list ap)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];
    ssize_t ret;

    ret = v9fs_iov_vunmarshal(elem->out_sg, elem->out_num, offset, 1, fmt, ap);
    if (ret < 0) {
        VirtIODevice *vdev = VIRTIO_DEVICE(v);

        virtio_error(vdev, "Failed to decode VirtFS request type %d", pdu->id);
    }
    return ret;
}

static void coroutine_fn
virtio_init_in_iov_from_pdu(V9fsPDU *pdu, struct iovec **piov,
                            unsigned int *pniov, size_t size)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];
    size_t buf_size = iov_size(elem->in_sg, elem->in_num);

    if (buf_size < size) {
        VirtIODevice *vdev = VIRTIO_DEVICE(v);

        virtio_error(vdev,
                     "VirtFS reply type %d needs %zu bytes, buffer has %zu",
                     pdu->id + 1, size, buf_size);
    }

    *piov = elem->in_sg;
    *pniov = elem->in_num;
}

static void coroutine_fn
virtio_init_out_iov_from_pdu(V9fsPDU *pdu, struct iovec **piov,
                             unsigned int *pniov, size_t size)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];
    size_t buf_size = iov_size(elem->out_sg, elem->out_num);

    if (buf_size < size) {
        VirtIODevice *vdev = VIRTIO_DEVICE(v);

        virtio_error(vdev,
                     "VirtFS request type %d needs %zu bytes, buffer has %zu",
                     pdu->id, size, buf_size);
    }

    *piov = elem->out_sg;
    *pniov = elem->out_num;
}

static size_t coroutine_fn virtio_9p_msize_limit(V9fsState *s)
{
    const size_t guestPageSize = 4096;
    return (VIRTQUEUE_MAX_SIZE - 2) * guestPageSize;
}

static size_t coroutine_fn virtio_9p_response_buffer_size(V9fsPDU *pdu)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];

    return iov_size(elem->in_sg, elem->in_num);
}

static const V9fsTransport virtio_9p_transport = {
    .pdu_vmarshal = virtio_pdu_vmarshal,
    .pdu_vunmarshal = virtio_pdu_vunmarshal,
    .init_in_iov_from_pdu = virtio_init_in_iov_from_pdu,
    .init_out_iov_from_pdu = virtio_init_out_iov_from_pdu,
    .push_and_notify = virtio_9p_push_and_notify,
    .msize_limit = virtio_9p_msize_limit,
    .response_buffer_size = virtio_9p_response_buffer_size,
};

/*
 * The requests that were in flight when the snapshot was taken.
 *
 * VMSTATE_VIRTIO_DEVICE carries the queue itself -- indices, features, config
 * -- but not `elems`, which is this device's own record of the
 * VirtQueueElements it has popped and not yet pushed back. The queue's indices
 * say the device has taken those requests, so the guest will never offer them
 * again: without them it waits for replies the host has forgotten it owes.
 *
 * Upstream does not need this because upstream does not get here: a 9p export
 * installs a migration blocker (see v9fs_attach(), where tctiSH removes it).
 *
 * A VirtQueueElement is not a plain struct -- qemu_put_virtqueue_element()
 * writes the guest addresses and lengths it was built from, and the loader
 * re-maps them -- so the array has its own VMStateInfo.
 */
static bool virtio_9p_elems_save(QEMUFile *f, void *pv, size_t size,
                                 const VMStateField *field, JSONWriter *vmdesc,
                                 Error **errp)
{
    V9fsVirtioState *v = container_of(pv, V9fsVirtioState, elems);
    unsigned i;

    for (i = 0; i < MAX_REQ; i++) {
        if (v->elems[i] == NULL) {
            qemu_put_be32(f, 0);
        } else {
            qemu_put_be32(f, 1);
            qemu_put_virtqueue_element(VIRTIO_DEVICE(v), f, v->elems[i]);
        }
    }
    return true;
}

/*
 * Takes PDU `i` off the free list for a restored request. A PDU's index is its
 * slot in elems[], so until the restored request has run no new request may be
 * given the same one.
 */
static bool virtio_9p_claim_pdu(V9fsState *s, unsigned i)
{
    V9fsPDU *pdu;

    QLIST_FOREACH(pdu, &s->free_list, next) {
        if (pdu->idx == i) {
            QLIST_REMOVE(pdu, next);
            QLIST_INSERT_HEAD(&s->active_list, pdu, next);
            return true;
        }
    }
    return false;
}

static bool virtio_9p_elems_load(QEMUFile *f, void *pv, size_t size,
                                 const VMStateField *field, Error **errp)
{
    V9fsVirtioState *v = container_of(pv, V9fsVirtioState, elems);
    unsigned i;

    for (i = 0; i < MAX_REQ; i++) {
        VirtQueueElement *elem;

        if (!qemu_get_be32(f)) {
            continue;
        }
        elem = qemu_get_virtqueue_element(VIRTIO_DEVICE(v), f,
                                          sizeof(VirtQueueElement));

        /*
         * Still being served: this is a load into the process that saved it,
         * as `unpark` does, and the request is the same one, outlasting the
         * stop's drain. It will answer for itself.
         */
        if (v->elems[i]) {
            g_free(elem);
            continue;
        }
        if (!virtio_9p_claim_pdu(&v->state, i)) {
            error_setg(errp, "virtio-9p request slot %u is in use", i);
            g_free(elem);
            return false;
        }
        v->elems[i] = elem;
        v->resubmit[i] = true;
    }
    return true;
}

static const VMStateInfo vmstate_info_virtio_9p_elems = {
    .name = "virtio-9p-elems",
    .load = virtio_9p_elems_load,
    .save = virtio_9p_elems_save,
};

/*
 * Once the VM runs again: the restored requests, then whatever the guest queued
 * while it was stopped.
 *
 * Nothing answers restored requests otherwise: the 9p core only ever sees a
 * request through handle_9p_output(), which pops new ones. They run from
 * scratch, which is safe because none of them had replied, and the server
 * state they refer to -- fids, above all -- is restored with them.
 */
static void virtio_9p_resubmit(V9fsVirtioState *v, bool flushes)
{
    unsigned i;

    for (i = 0; i < MAX_REQ; i++) {
        V9fsPDU *pdu = &v->state.pdus[i];
        VirtQueueElement *elem = v->elems[i];
        P9MsgHeader out;

        if (!v->resubmit[i]) {
            continue;
        }
        if (iov_to_buf(elem->out_sg, elem->out_num, 0, &out, 7) != 7) {
            v->resubmit[i] = false;
            virtio_error(VIRTIO_DEVICE(v), "A restored VirtFS request is "
                         "malformed");
            virtqueue_detach_element(v->vq, elem, 0);
            g_free(elem);
            v->elems[i] = NULL;
            pdu_free(pdu);
            continue;
        }
        if ((out.id == P9_TFLUSH) != flushes) {
            continue;
        }
        v->resubmit[i] = false;
        pdu_submit(pdu, &out);
    }
}

static void virtio_9p_resume(void *opaque)
{
    V9fsVirtioState *v = opaque;

    /* Stopped again before this ran: the next start schedules it again. */
    if (!runstate_is_running()) {
        return;
    }

    /*
     * A Tflush finds the request it cancels by tag among the active PDUs,
     * which a restored request only has once submitted. So flushes go last,
     * and nothing new is taken off the queue until all of them have gone.
     * Otherwise a flush could answer before the request it cancels is running
     * again, and that request's reply would then reach a tag the guest has
     * already reused.
     */
    virtio_9p_resubmit(v, false);
    virtio_9p_resubmit(v, true);
    v->stopped = false;

    handle_9p_output(VIRTIO_DEVICE(v), v->vq);
}

/* Whether a request is being served, rather than waiting to be resubmitted. */
static bool virtio_9p_busy(V9fsVirtioState *v)
{
    V9fsPDU *pdu;

    QLIST_FOREACH(pdu, &v->state.active_list, next) {
        if (!v->resubmit[pdu->idx]) {
            return true;
        }
    }
    return false;
}

static void virtio_9p_drain_wake(void *opaque)
{
}

/*
 * How long a stop waits for the requests being served. Local files answer in
 * milliseconds, so this is only reached by something like a throttled fsdev,
 * and then the requests left are saved and run again after a resume.
 */
#define VIRTIO_9P_DRAIN_MS 2000

static void virtio_9p_drain(V9fsVirtioState *v)
{
    AioContext *ctx = qemu_get_aio_context();
    int64_t deadline = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                       VIRTIO_9P_DRAIN_MS;
    QEMUTimer *wake = aio_timer_new(ctx, QEMU_CLOCK_REALTIME, SCALE_MS,
                                    virtio_9p_drain_wake, NULL);

    /* The timer only wakes aio_poll(), so a stuck request cannot hold it. */
    timer_mod(wake, deadline);
    while (virtio_9p_busy(v) &&
           qemu_clock_get_ms(QEMU_CLOCK_REALTIME) < deadline) {
        aio_poll(ctx, true);
    }
    timer_free(wake);
}

/*
 * Quiesces the device while the VM is stopped, which is when it is saved.
 *
 * A request still being served when the save runs can finish during it: its
 * completion runs from the main AioContext, which the save itself polls while
 * writing the stream. Its reply would then land in guest RAM that has already
 * been saved, while the queue state saved after it says it was answered. So a
 * stop first lets the requests being served finish, and then takes no new ones
 * off the queue until the VM runs again. Requests the guest queues meanwhile
 * stay in its ring, which the snapshot captures consistently as guest RAM.
 */
static void virtio_9p_vm_change(void *opaque, bool running, RunState state)
{
    V9fsVirtioState *v = opaque;

    if (!running) {
        v->stopped = true;
        virtio_9p_drain(v);
        return;
    }

    /*
     * Scheduled rather than run here: vm_start() calls this before the vCPUs
     * resume, and a request can complete, and notify the guest, before
     * pdu_submit() returns. The device stays stopped until it has run.
     */
    qemu_bh_schedule(v->resume_bh);
}

/*
 * Forgets the restored requests that have not run yet, for a reset. The queue
 * they came from is being reset with them, so there is nobody to reply to, and
 * v9fs_reset() waits for the active list to empty, which their PDUs would keep
 * it from doing.
 */
static void virtio_9p_drop_resubmit(V9fsVirtioState *v)
{
    unsigned i;

    for (i = 0; i < MAX_REQ; i++) {
        if (v->resubmit[i]) {
            v->resubmit[i] = false;
            g_free(v->elems[i]);
            v->elems[i] = NULL;
            pdu_free(&v->state.pdus[i]);
        }
    }
}

static void virtio_9p_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    V9fsVirtioState *v = VIRTIO_9P(dev);
    V9fsState *s = &v->state;
    FsDriverEntry *fse = get_fsdev_fsentry(s->fsconf.fsdev_id);

    if (qtest_enabled() && fse) {
        fse->export_flags |= V9FS_NO_PERF_WARN;
    }

    if (v9fs_device_realize_common(s, &virtio_9p_transport, errp)) {
        return;
    }

    v->config_size = sizeof(struct virtio_9p_config) + strlen(s->fsconf.tag);
    virtio_init(vdev, VIRTIO_ID_9P, v->config_size);
    v->vq = virtio_add_queue(vdev, MAX_REQ, handle_9p_output);
    v->resume_bh = virtio_bh_new_guarded(dev, virtio_9p_resume, v);
    v->vm_change = qdev_add_vm_change_state_handler(dev, virtio_9p_vm_change,
                                                    NULL, v);
}

static void virtio_9p_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    V9fsVirtioState *v = VIRTIO_9P(dev);
    V9fsState *s = &v->state;

    qemu_del_vm_change_state_handler(v->vm_change);
    qemu_bh_delete(v->resume_bh);
    virtio_9p_drop_resubmit(v);
    v9fs_reset(s); /* cancel all in-flight PDUs to prevent UAF */
    virtio_delete_queue(v->vq);
    virtio_cleanup(vdev);
    v9fs_device_unrealize_common(s);
}

/* virtio-9p device */

/* Nothing to carry until the guest has sent Tversion. */
static bool virtio_9p_session_needed(void *opaque)
{
    V9fsVirtioState *v = opaque;

    return v->state.proto_version != 0;
}

static const VMStateDescription vmstate_virtio_9p_session = {
    .name = "virtio-9p-device/session",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = virtio_9p_session_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_SINGLE(state, V9fsVirtioState, 1, vmstate_info_v9fs_session,
                       V9fsState),
        VMSTATE_END_OF_LIST()
    },
};

/*
 * This device's own state, inside VMSTATE_VIRTIO_DEVICE.
 *
 * It has to be here rather than in vmstate_virtio_9p: virtio_load() reads the
 * generic "virtio" subsections at the end of the VMSTATE_VIRTIO_DEVICE field,
 * and any subsection of "virtio-9p" would pass their name-prefix check and be
 * refused as unknown.
 */
static const VMStateDescription vmstate_virtio_9p_device = {
    .name = "virtio-9p-device",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        {
            .name = "elems",
            .info = &vmstate_info_virtio_9p_elems,
            .flags = VMS_SINGLE,
            .offset = offsetof(V9fsVirtioState, elems),
            .size = sizeof_field(V9fsVirtioState, elems),
        },
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_virtio_9p_session,
        NULL
    },
};

static const VMStateDescription vmstate_virtio_9p = {
    .name = "virtio-9p",
    .minimum_version_id = 1,
    .version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static const Property virtio_9p_properties[] = {
    DEFINE_PROP_STRING("mount_tag", V9fsVirtioState, state.fsconf.tag),
    DEFINE_PROP_STRING("fsdev", V9fsVirtioState, state.fsconf.fsdev_id),
};

static void virtio_9p_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_9p_properties);
    dc->vmsd = &vmstate_virtio_9p;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = virtio_9p_device_realize;
    vdc->unrealize = virtio_9p_device_unrealize;
    vdc->get_features = virtio_9p_get_features;
    vdc->get_config = virtio_9p_get_config;
    vdc->reset = virtio_9p_reset;
    vdc->vmsd = &vmstate_virtio_9p_device;
}

static const TypeInfo virtio_device_info = {
    .name = TYPE_VIRTIO_9P,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(V9fsVirtioState),
    .class_init = virtio_9p_class_init,
};

static void virtio_9p_register_types(void)
{
    type_register_static(&virtio_device_info);
}

type_init(virtio_9p_register_types)
