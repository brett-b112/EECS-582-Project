/*
 * Exposes /dev/photon_ring so that userspace can:
 *   1. ioctl(PHOTON_IOC_SET_KEY) to provide the 32-byte master key (once).
 *   2. read() in a loop to receive length-prefixed encrypted frames.
 *
 * frame wire format (little-endian, packed):
 *   u32  frame_len          — byte count of the body that follows
 *   u64  sequence_num       — plaintext monotonic counter
 *   u64  rotation_num       — HKDF key rotation index
 *   u8   iv[12]             — AES-GCM IV
 *   u16  encrypted_len      — length of ciphertext (== sizeof(photon_event))
 *   u8   auth_tag[16]       — AES-GCM authentication tag
 *   u8   encrypted_data[]   — ciphertext of photon_event
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ioctl.h>
#include "cdev_ch.h"
#include "../include/crypto.h"


/* maximum body size: photon_encrypted_msg fixed fields + sizeof(photon_event) */
#define PHOTON_FRAME_BODY_MAX \
    (sizeof(u64) + sizeof(u64) + 12 + sizeof(u16) + 16 + sizeof(struct photon_event))

struct frame_slot {
    u8   data[PHOTON_FRAME_SLOT_SIZE];
    u32  len;       /* total bytes valid in data[] including the u32 header */
};

struct photon_ring_buf {
    struct frame_slot  *slots;
    u32                 head;       /* next write position */
    u32                 tail;       /* next read position  */
    u32                 capacity;
    u32                 dropped;
    spinlock_t          lock;
};

static struct photon_ring_buf g_ring;

static int ring_buf_init(struct photon_ring_buf *rb, u32 capacity)
{
    rb->slots = kcalloc(capacity, sizeof(struct frame_slot), GFP_KERNEL);
    if (!rb->slots)
        return -ENOMEM;
    rb->head     = 0;
    rb->tail     = 0;
    rb->capacity = capacity;
    rb->dropped  = 0;
    spin_lock_init(&rb->lock);
    return 0;
}

static void ring_buf_free(struct photon_ring_buf *rb)
{
    if (rb->slots) {
        memzero_explicit(rb->slots,
                         rb->capacity * sizeof(struct frame_slot));
        kfree(rb->slots);
        rb->slots = NULL;
    }
}

static inline bool ring_buf_full(struct photon_ring_buf *rb)
{
    return ((rb->head + 1) % rb->capacity) == rb->tail;
}

static inline bool ring_buf_empty(struct photon_ring_buf *rb)
{
    return rb->head == rb->tail;
}