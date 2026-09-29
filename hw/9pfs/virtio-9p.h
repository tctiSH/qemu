#ifndef QEMU_VIRTIO_9P_H
#define QEMU_VIRTIO_9P_H

#include "standard-headers/linux/virtio_9p.h"
#include "hw/virtio/virtio.h"
#include "9p.h"
#include "qom/object.h"

struct V9fsVirtioState {
    VirtIODevice parent_obj;
    VirtQueue *vq;
    size_t config_size;
    VirtQueueElement *elems[MAX_REQ];
    /* Requests restored from a snapshot, to be run again when the VM does. */
    bool resubmit[MAX_REQ];
    /* Take no new requests: set on stop, cleared by virtio_9p_resume(). */
    bool stopped;
    QEMUBH *resume_bh;
    VMChangeStateEntry *vm_change;
    V9fsState state;
};

#define TYPE_VIRTIO_9P "virtio-9p-device"
OBJECT_DECLARE_SIMPLE_TYPE(V9fsVirtioState, VIRTIO_9P)

#endif
