#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/string.h>
#include "event_manager.h"
#include "cdev_ch.h"
#include "crypto.h"

/* global sequence counter — monotonically increasing across all CPUs */
static atomic64_t g_sequence_counter = ATOMIC64_INIT(0);

/* -------------------------------------------------------------------------
 * Per-CPU event ring buffer
 * -------------------------------------------------------------------------*/
struct event_buffer {
    spinlock_t          lock;
    struct photon_event *events;
    u32                 head;
    u32                 tail;
    u32                 capacity;
    u32                 dropped;
};

static DEFINE_PER_CPU(struct event_buffer, event_buffers);

#define EVENT_BUFFER_SIZE 256   /* slots per CPU */

/* -------------------------------------------------------------------------
 * Statistics
 * -------------------------------------------------------------------------*/
static struct {
    atomic64_t total_events;
    atomic64_t total_dropped;
    atomic64_t total_sent;
    atomic64_t send_failures;
} g_stats;

/* -------------------------------------------------------------------------
 * Buffer helpers
 * -------------------------------------------------------------------------*/

static int init_event_buffer(struct event_buffer *buf)
{
    spin_lock_init(&buf->lock);
    buf->events = kmalloc_array(EVENT_BUFFER_SIZE,
                                sizeof(struct photon_event),
                                GFP_KERNEL);
    if (!buf->events)
        return -ENOMEM;
    buf->head     = 0;
    buf->tail     = 0;
    buf->capacity = EVENT_BUFFER_SIZE;
    buf->dropped  = 0;
    return 0;
}

static void free_event_buffer(struct event_buffer *buf)
{
    if (buf->events) {
        memzero_explicit(buf->events,
                         buf->capacity * sizeof(struct photon_event));
        kfree(buf->events);
        buf->events = NULL;
    }
}

static inline bool buffer_is_full(struct event_buffer *buf)
{
    return ((buf->head + 1) % buf->capacity) == buf->tail;
}

static inline bool buffer_is_empty(struct event_buffer *buf)
{
    return buf->head == buf->tail;
}

static int enqueue_event(struct photon_event *event)
{
    struct event_buffer *buf;
    unsigned long flags;
    int ret = 0;

    buf = &get_cpu_var(event_buffers);
    spin_lock_irqsave(&buf->lock, flags);

    if (buffer_is_full(buf)) {
        buf->dropped++;
        atomic64_inc(&g_stats.total_dropped);
        ret = -ENOSPC;
        goto out;
    }

    memcpy(&buf->events[buf->head], event, sizeof(struct photon_event));
    buf->head = (buf->head + 1) % buf->capacity;

out:
    spin_unlock_irqrestore(&buf->lock, flags);
    put_cpu_var(event_buffers);
    return ret;
}

static void flush_event_buffer(struct event_buffer *buf)
{
    unsigned long flags;
    struct photon_event event;
    int ret;

    spin_lock_irqsave(&buf->lock, flags);

    while (!buffer_is_empty(buf)) {
        memcpy(&event, &buf->events[buf->tail], sizeof(struct photon_event));
        buf->tail = (buf->tail + 1) % buf->capacity;

        /* release lock while doing I/O so other CPUs can enqueue */
        spin_unlock_irqrestore(&buf->lock, flags);

        ret = photon_send_encrypted_event(&event);
        if (ret) {
            atomic64_inc(&g_stats.send_failures);
            printk(KERN_WARNING "[PHOTON RING] Failed to send event: %d\n", ret);
        } else {
            atomic64_inc(&g_stats.total_sent);
        }

        spin_lock_irqsave(&buf->lock, flags);
    }

    spin_unlock_irqrestore(&buf->lock, flags);
}

static void flush_all_buffers(void)
{
    int cpu;
    for_each_possible_cpu(cpu)
        flush_event_buffer(&per_cpu(event_buffers, cpu));
}

/* -------------------------------------------------------------------------
 * photon_log_event
 *
 * The redesigned API takes an explicit severity parameter and captures
 * caller_pid / caller_comm internally so detectors no longer need to
 * repeat those fields in their payload structs.
 * -------------------------------------------------------------------------*/
int photon_log_event(u32 event_type, u32 detector_id, u8 severity,
                     const void *data, u16 data_len)
{
    struct photon_event event;
    int ret;

    if (data_len > PHOTON_MAX_EVENT_DATA) {
        printk(KERN_WARNING "[PHOTON RING] Event data too large: %u (max %u)\n",
               data_len, PHOTON_MAX_EVENT_DATA);
        return -EINVAL;
    }

    memset(&event, 0, sizeof(event));

    /* --- envelope fields ------------------------------------------------- */
    event.sequence_num = atomic64_inc_return(&g_sequence_counter);
    event.timestamp_ns = ktime_get_real_ns();
    event.event_type   = event_type;
    event.detector_id  = detector_id;
    event.severity     = severity;

    /* Capture caller identity here once, so no payload struct needs it */
    event.caller_pid   = (u32)current->pid;
    strncpy(event.caller_comm, current->comm, sizeof(event.caller_comm) - 1);

    /* --- payload --------------------------------------------------------- */
    event.data_len = data_len;
    if (data && data_len > 0)
        memcpy(event.data, data, data_len);

    atomic64_inc(&g_stats.total_events);

    ret = enqueue_event(&event);
    if (ret) {
        /* Buffer full — try flushing once then retry */
        flush_all_buffers();
        ret = enqueue_event(&event);
        if (ret) {
            printk(KERN_WARNING "[PHOTON RING] Event queue full, dropping event "
                   "(type=%u sev=%u)\n", event_type, severity);
            return ret;
        }
    }

    /*
     * Flush immediately: security detectors need low latency, not batching.
     * Each event reaches userspace as soon as it is enqueued.
     */
    flush_all_buffers();
    return 0;
}

/* -------------------------------------------------------------------------
 * Heartbeat
 * -------------------------------------------------------------------------*/
int photon_send_heartbeat(void)
{
    struct system_data hb;

    hb.uptime_ns        = ktime_get_ns();
    hb.events_sent      = (u64)atomic64_read(&g_stats.total_sent);
    hb.events_dropped   = (u64)atomic64_read(&g_stats.total_dropped);
    hb.new_rotation_num = 0;   /* 0 indicates heartbeat (not key rotation) */

    return photon_log_event(PHOTON_EVENT_SYSTEM_HEARTBEAT,
                            0,
                            PHOTON_SEV_INFO,
                            &hb, sizeof(hb));
}

/* -------------------------------------------------------------------------
 * Init / exit
 * -------------------------------------------------------------------------*/
int event_manager_init(void)
{
    int cpu, ret;

    printk(KERN_INFO "[PHOTON RING] Initializing event manager...\n");

    for_each_possible_cpu(cpu) {
        struct event_buffer *buf = &per_cpu(event_buffers, cpu);
        ret = init_event_buffer(buf);
        if (ret) {
            printk(KERN_ERR "[PHOTON RING] Failed to init buffer for CPU %d: %d\n",
                   cpu, ret);
            goto cleanup_buffers;
        }
    }

    atomic64_set(&g_stats.total_events,   0);
    atomic64_set(&g_stats.total_dropped,  0);
    atomic64_set(&g_stats.total_sent,     0);
    atomic64_set(&g_stats.send_failures,  0);

    ret = crypto_layer_init();
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to init crypto: %d\n", ret);
        goto cleanup_buffers;
    }

    ret = cdev_channel_init();
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to init cdev: %d\n", ret);
        goto cleanup_crypto;
    }

    printk(KERN_INFO "[PHOTON RING] Event manager initialized "
           "(per-CPU buffer: %d slots, max payload: %d bytes)\n",
           EVENT_BUFFER_SIZE, PHOTON_MAX_EVENT_DATA);
    return 0;

cleanup_crypto:
    crypto_layer_exit();
cleanup_buffers:
    for_each_possible_cpu(cpu)
        free_event_buffer(&per_cpu(event_buffers, cpu));
    return ret;
}

void event_manager_exit(void)
{
    int cpu;

    printk(KERN_INFO "[PHOTON RING] Shutting down event manager...\n");

    flush_all_buffers();

    printk(KERN_INFO "[PHOTON RING] Event statistics:\n");
    printk(KERN_INFO "[PHOTON RING]   Total:        %lld\n",
           atomic64_read(&g_stats.total_events));
    printk(KERN_INFO "[PHOTON RING]   Sent:         %lld\n",
           atomic64_read(&g_stats.total_sent));
    printk(KERN_INFO "[PHOTON RING]   Dropped:      %lld\n",
           atomic64_read(&g_stats.total_dropped));
    printk(KERN_INFO "[PHOTON RING]   Send failures:%lld\n",
           atomic64_read(&g_stats.send_failures));

    cdev_channel_exit();
    crypto_layer_exit();

    for_each_possible_cpu(cpu)
        free_event_buffer(&per_cpu(event_buffers, cpu));

    printk(KERN_INFO "[PHOTON RING] Event manager shut down\n");
}

u64 photon_get_sequence(void)
{
    return atomic64_read(&g_sequence_counter);
}