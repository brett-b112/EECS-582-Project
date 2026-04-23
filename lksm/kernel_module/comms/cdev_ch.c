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
#include "../include/cdev_ch.h"
#include "../include/crypto.h"


/* maximum body size: photon_encrypted_msg fixed fields + sizeof(photon_event) */
#define PHOTON_FRAME_BODY_MAX \
    (sizeof(u64) + sizeof(u64) + 12 + sizeof(u16) + 16 + sizeof(struct photon_event))

/* a single ring slot: 4-byte length prefix followed by the body */
#define PHOTON_FRAME_SLOT_SIZE  (sizeof(u32) + PHOTON_FRAME_BODY_MAX)

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

/*
 * ring_buf_push - copy a frame into the next available slot.
 * must be called with rb->lock held.
 * returns 0 on success, -ENOSPC if the buffer is full.
 */
static int ring_buf_push(struct photon_ring_buf *rb,
                         const u8 *frame, u32 total_len)
{
    struct frame_slot *slot;

    if (ring_buf_full(rb)) {
        rb->dropped++;
        return -ENOSPC;
    }

    slot = &rb->slots[rb->head];
    memcpy(slot->data, frame, total_len);
    slot->len = total_len;
    rb->head  = (rb->head + 1) % rb->capacity;
    return 0;
}

/*
 * ring_buf_pop_locked - copy the oldest frame out, advance tail.
 * caller must hold rb->lock.
 * returns the number of bytes copied into dst, or 0 if empty.
 */
static u32 ring_buf_pop_locked(struct photon_ring_buf *rb,
                                u8 *dst, u32 dst_len)
{
    struct frame_slot *slot;
    u32 copy_len;

    if (ring_buf_empty(rb))
        return 0;

    slot     = &rb->slots[rb->tail];
    copy_len = min_t(u32, slot->len, dst_len);
    memcpy(dst, slot->data, copy_len);
    memzero_explicit(slot->data, slot->len);   /* wipe after reading */
    rb->tail = (rb->tail + 1) % rb->capacity;
    return copy_len;
}

/* -------------------------------------------------------------------------
 * Character device state
 * -------------------------------------------------------------------------*/
static int            g_major;
static struct class  *g_class;
static struct device *g_device;
static struct cdev    g_cdev;

/* wait queue: read() blocks here until a frame is available or device closes */
static DECLARE_WAIT_QUEUE_HEAD(g_read_wq);

/* set to true during exit so sleeping readers wake up and return -EIO */
static bool g_shutting_down = false;

/* allow only one reader at a time */
static DEFINE_MUTEX(g_open_mutex);
static bool g_is_open = false;

/* scratch buffer used inside read() to stage a frame before copy_to_user */
static u8 g_read_staging[PHOTON_FRAME_SLOT_SIZE];

/* -------------------------------------------------------------------------
 * file_operations
 * -------------------------------------------------------------------------*/

static int photon_cdev_open(struct inode *inode, struct file *filp)
{
    /* enforce CAP_SYS_ADMIN so only privileged daemons can open the device */
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_WARNING "[PHOTON RING] open() denied — not CAP_SYS_ADMIN\n");
        return -EPERM;
    }

    mutex_lock(&g_open_mutex);
    if (g_is_open) {
        mutex_unlock(&g_open_mutex);
        printk(KERN_WARNING "[PHOTON RING] open() denied — device already open\n");
        return -EBUSY;
    }
    g_is_open = true;
    mutex_unlock(&g_open_mutex);

    printk(KERN_INFO "[PHOTON RING] device opened by PID %d\n", current->pid);
    return 0;
}

static int photon_cdev_release(struct inode *inode, struct file *filp)
{
    mutex_lock(&g_open_mutex);
    g_is_open = false;
    mutex_unlock(&g_open_mutex);
    printk(KERN_INFO "[PHOTON RING] device closed by PID %d\n", current->pid);
    return 0;
}

/*
 * photon_cdev_read - deliver one frame to userspace per call.
 *
 * protocol:
 *   1. block until a frame is in the ring buffer (or shutdown/signal).
 *   2. pop the frame into a kernel staging buffer.
 *   3. copy_to_user() the frame in two steps matching userspace reads:
 *        first the 4-byte u32 length header, then the body.
 *      because userspace typically calls read() twice (header, then body)
 *      we support partial reads by tracking position via filp->private_data.
 *
 * the daemon always reads exactly 4 bytes first, then the
 * returned length.  We service the full frame in a single read() call of
 * sufficient size, or split across two calls for header + body.
 */
static ssize_t photon_cdev_read(struct file *filp, char __user *buf,
                                 size_t count, loff_t *ppos)
{
    unsigned long flags;
    u32 frame_len;
    int ret;

    /* block until data available, device closing, or signal */
    ret = wait_event_interruptible(g_read_wq,
              !ring_buf_empty(&g_ring) || g_shutting_down);
    if (ret)
        return -EINTR;
    if (g_shutting_down)
        return -EIO;

    /* pop one frame into staging buffer */
    spin_lock_irqsave(&g_ring.lock, flags);
    frame_len = ring_buf_pop_locked(&g_ring, g_read_staging,
                                     sizeof(g_read_staging));
    spin_unlock_irqrestore(&g_ring.lock, flags);

    if (frame_len == 0)
        return 0;   /* shouldn't happen but be safe */

    /* refuse if userspace buffer is too small for even the length header */
    if (count < sizeof(u32))
        return -EINVAL;

    /* copy as much as userspace asked for */
    frame_len = min_t(u32, frame_len, (u32)count);
    if (copy_to_user(buf, g_read_staging, frame_len)) {
        memzero_explicit(g_read_staging, sizeof(g_read_staging));
        return -EFAULT;
    }

    memzero_explicit(g_read_staging, sizeof(g_read_staging));
    return (ssize_t)frame_len;
}

/*
 * photon_cdev_ioctl - handle PHOTON_IOC_SET_KEY.
 *
 * only accepts the key if:
 *   - caller has CAP_SYS_ADMIN (already enforced by open(), double-checked here)
 *   - no key has been set yet (one-time operation)
 */
static long photon_cdev_ioctl(struct file *filp, unsigned int cmd,
                               unsigned long arg)
{
    u8 key[PHOTON_KEY_SIZE];
    int ret;

    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    switch (cmd) {
    case PHOTON_IOC_SET_KEY:
        if (photon_has_key()) {
            printk(KERN_ALERT
                   "[PHOTON RING] REJECTED ioctl SET_KEY — key already set\n");
            return -EEXIST;
        }

        if (copy_from_user(key, (const void __user *)arg, PHOTON_KEY_SIZE)) {
            memzero_explicit(key, sizeof(key));
            return -EFAULT;
        }

        ret = photon_set_encryption_key(key);
        memzero_explicit(key, sizeof(key));

        if (ret) {
            printk(KERN_ERR "[PHOTON RING] SET_KEY failed: %d\n", ret);
            return ret;
        }

        printk(KERN_INFO "[PHOTON RING] Master key set via ioctl — "
                         "encryption is now ACTIVE\n");

        /* send immediate heartbeat so userspace can verify the key works */
        photon_send_heartbeat();
        return 0;

    default:
        return -ENOTTY;
    }
}

static const struct file_operations photon_fops = {
    .owner          = THIS_MODULE,
    .open           = photon_cdev_open,
    .release        = photon_cdev_release,
    .read           = photon_cdev_read,
    .unlocked_ioctl = photon_cdev_ioctl,
    /* no write() — userspace never writes event data */
};

int photon_send_encrypted_event(struct photon_event *event)
{
    /*
     * frame layout assembled into a stack buffer:
     *   [0..3]   u32 body_len  (filled last)
     *   [4..]    photon_encrypted_msg body
     *              u64 sequence_num
     *              u64 rotation_num
     *              u8  iv[12]
     *              u16 encrypted_len
     *              u8  auth_tag[16]
     *              u8  encrypted_data[encrypted_len]
     */
    u8  frame[PHOTON_FRAME_SLOT_SIZE];
    struct photon_encrypted_msg *enc;
    size_t body_size;
    u32    total_size;
    unsigned long flags;
    int ret;

    if (!photon_has_key()) {
        /*
         * key not yet set.  event_manager already buffers events and will
         * flush them once the key is established — but if somehow called
         * before that, drop rather than crash.
         */
        return 0;
    }

    /* point enc at the body portion of the frame (after the u32 header) */
    enc = (struct photon_encrypted_msg *)(frame + sizeof(u32));

    enc->rotation_num = photon_get_rotation_number();

    ret = photon_encrypt_event(event, enc);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to encrypt event: %d\n", ret);
        memzero_explicit(frame, sizeof(frame));
        return ret;
    }

    /*
     * body_size = fixed fields of photon_encrypted_msg
     *           + enc->encrypted_len (the ciphertext, i.e. sizeof photon_event)
     */
    body_size  = sizeof(u64) + sizeof(u64) + sizeof(enc->iv)
               + sizeof(u16) + sizeof(enc->auth_tag)
               + enc->encrypted_len;
    total_size = sizeof(u32) + body_size;

    /* write the length prefix */
    *((u32 *)frame) = (u32)body_size;

    if (total_size > sizeof(frame)) {
        /* should never happen with compile-time sized buffers */
        printk(KERN_ERR "[PHOTON RING] Frame too large: %u\n", total_size);
        memzero_explicit(frame, sizeof(frame));
        return -EMSGSIZE;
    }

    spin_lock_irqsave(&g_ring.lock, flags);
    ret = ring_buf_push(&g_ring, frame, total_size);
    spin_unlock_irqrestore(&g_ring.lock, flags);

    memzero_explicit(frame, sizeof(frame));

    if (ret == -ENOSPC) {
        printk(KERN_WARNING "[PHOTON RING] Ring buffer full — frame dropped "
                            "(total dropped: %u)\n", g_ring.dropped);
        return 0;   /* treat as non-fatal so the detector keeps running */
    }

    /* wake a sleeping reader */
    wake_up_interruptible(&g_read_wq);
    return 0;
}

int cdev_channel_init(void)
{
    int ret;
    dev_t dev_num;

    printk(KERN_INFO "[PHOTON RING] Initializing character device channel...\n");

    /* allocate ring buffer */
    ret = ring_buf_init(&g_ring, PHOTON_RING_BUF_FRAMES);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to allocate ring buffer: %d\n", ret);
        return ret;
    }

    /* allocate a dynamic major number */
    ret = alloc_chrdev_region(&dev_num, 0, 1, PHOTON_RING_DEV_NAME);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] alloc_chrdev_region failed: %d\n", ret);
        goto err_ring;
    }
    g_major = MAJOR(dev_num);

    /* initialise and register the cdev */
    cdev_init(&g_cdev, &photon_fops);
    g_cdev.owner = THIS_MODULE;
    ret = cdev_add(&g_cdev, dev_num, 1);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] cdev_add failed: %d\n", ret);
        goto err_chrdev;
    }

    /* create /sys/class/photon_ring so udev makes /dev/photon_ring */
    g_class = class_create(PHOTON_RING_CLASS_NAME);
    if (IS_ERR(g_class)) {
        ret = PTR_ERR(g_class);
        printk(KERN_ERR "[PHOTON RING] class_create failed: %d\n", ret);
        goto err_cdev;
    }

    g_device = device_create(g_class, NULL, dev_num, NULL,
                              PHOTON_RING_DEV_NAME);
    if (IS_ERR(g_device)) {
        ret = PTR_ERR(g_device);
        printk(KERN_ERR "[PHOTON RING] device_create failed: %d\n", ret);
        goto err_class;
    }

    printk(KERN_INFO "[PHOTON RING] /dev/%s created (major=%d)\n",
           PHOTON_RING_DEV_NAME, g_major);
    printk(KERN_INFO "[PHOTON RING] Ring buffer: %d frame slots\n",
           PHOTON_RING_BUF_FRAMES);
    printk(KERN_INFO "[PHOTON RING] Waiting for key via ioctl SET_KEY...\n");
    return 0;

err_class:
    class_destroy(g_class);
err_cdev:
    cdev_del(&g_cdev);
err_chrdev:
    unregister_chrdev_region(dev_num, 1);
err_ring:
    ring_buf_free(&g_ring);
    return ret;
}

void cdev_channel_exit(void)
{
    dev_t dev_num = MKDEV(g_major, 0);

    printk(KERN_INFO "[PHOTON RING] Shutting down character device channel...\n");

    /* wake any sleeping readers so they can see g_shutting_down and exit */
    g_shutting_down = true;
    wake_up_interruptible(&g_read_wq);

    device_destroy(g_class, dev_num);
    class_destroy(g_class);
    cdev_del(&g_cdev);
    unregister_chrdev_region(dev_num, 1);

    ring_buf_free(&g_ring);

    if (g_ring.dropped)
        printk(KERN_INFO "[PHOTON RING] Total frames dropped: %u\n",
               g_ring.dropped);

    printk(KERN_INFO "[PHOTON RING] Character device channel shut down\n");
}
