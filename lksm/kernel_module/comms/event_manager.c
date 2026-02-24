#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include "../include/event_manager.h"
#include "../include/cdev_ch.h"
#include "../include/crypto.h"

/* global sequence counter - monotonically increasing */
static atomic64_t g_sequence_counter = ATOMIC64_INIT(0);

/* per-CPU event buffers for lock-free operation */
struct event_buffer {
    spinlock_t lock;
    struct photon_event *events;
    u32 head;
    u32 tail;
    u32 capacity;
    u32 dropped; // count of dropped events due to full buffer
};

static DEFINE_PER_CPU(struct event_buffer, event_buffers);

#define EVENT_BUFFER_SIZE 256 // per-CPU buffer size

/* stats */
struct event_stats {
    atomic64_t total_events;
    atomic64_t total_dropped;
    atomic64_t total_sent;
    atomic64_t encrypt_failures;
    atomic64_t send_failures;
};

static struct event_stats g_stats;

/** 
 * init_event_buffer - initialize a per-CPU event buffer
 */
static int init_event_buffer(struct event_buffer *buf) 
{
    spin_lock_init(&buf->lock);
    
    buf->events = kmalloc_array(EVENT_BUFFER_SIZE, 
                                sizeof(struct photon_event), 
                                GFP_KERNEL);
    if (!buf->events)
        return -ENOMEM;
    
    buf->head = 0;
    buf->tail = 0;
    buf->capacity = EVENT_BUFFER_SIZE;
    buf->dropped = 0;
    
    return 0;
}

/** 
 * free_event_buffer - free a per-CPU event buffer
 */
static void free_event_buffer(struct event_buffer *buf)
{
    if (buf->events) {
        // clear sensitive data before freeing
        memzero_explicit(buf->events,
            buf->capacity * sizeof(struct photon_event));
        kfree(buf->events);
        buf->events = NULL;
    }
}

/**
 * buffer_is_full - check if buffer is full
 */
static inline bool buffer_is_full(struct event_buffer *buf)
{
    return ((buf->head + 1) % buf->capacity) == buf->tail;
}

/**
 * buffer_is_empty - check if buffer is empty
 */
static inline bool buffer_is_empty(struct event_buffer *buf)
{
    return buf->head == buf->tail;
}

/**
 * enqueue_event - add event to per-CPU buffer
 */
static int enqueue_event(struct photon_event *event)
{
    struct event_buffer *buf;
    unsigned long flags;
    int ret = 0;

    // get per-CPU buffer (disables preemption)
    buf = &get_cpu_var(event_buffers);

    spin_lock_irqsave(&buf->lock, flags);

    if (buffer_is_full(buf)) {
        buf->dropped++;
        atomic64_inc(&g_stats.total_dropped);
        ret = -ENOSPC;
        goto out;
    }

    // copy event to buffer
    memcpy(&buf->events[buf->head], event, sizeof(struct photon_event));
    buf->head = (buf->head + 1) % buf->capacity;

out:
    spin_unlock_irqrestore(&buf->lock, flags);
    put_cpu_var(event_buffers);

    return ret;
}

/**
 * flush_event_buffer - send all events from a buffer to userspace
 */
static void flush_event_buffer(struct event_buffer *buf)
{
    unsigned long flags;
    struct photon_event event;
    int ret;
    
    spin_lock_irqsave(&buf->lock, flags);
    
    while (!buffer_is_empty(buf)) {
        // copy event out of buffer
        memcpy(&event, &buf->events[buf->tail], sizeof(struct photon_event));
        buf->tail = (buf->tail + 1) % buf->capacity;
        
        // unlock while sending (avoid holding lock during I/O)
        spin_unlock_irqrestore(&buf->lock, flags);
        
        // encrypt and send event
        ret = photon_send_encrypted_event(&event);
        if (ret) {
            atomic64_inc(&g_stats.send_failures);
            printk(KERN_WARNING "[PHOTON RING] Failed to send event: %d\n", ret);
        } else {
            atomic64_inc(&g_stats.total_sent);
        }
        
        // re-acquire lock for next iteration
        spin_lock_irqsave(&buf->lock, flags);
    }
    
    spin_unlock_irqrestore(&buf->lock, flags);
}

/**
 * flush_all_buffers - flush all per-CPU buffers
 */
static void flush_all_buffers(void)
{
    int cpu;
    
    for_each_possible_cpu(cpu) {
        struct event_buffer *buf = &per_cpu(event_buffers, cpu);
        flush_event_buffer(buf);
    }
}

int event_manager_init(void)
{
    int cpu;
    int ret;

    printk(KERN_INFO "[PHOTON RING] Initializing event manager...\n");

    // initialize per-CPU buffers
    for_each_possible_cpu(cpu) {
        struct event_buffer *buf = &per_cpu(event_buffers, cpu);
        ret = init_event_buffer(buf);
        if (ret) {
            printk(KERN_ERR "[PHOTON RING] Failed to init buffer for CPU %d\n", cpu);
            goto cleanup_buffers;
        }
    }

    // initialize statistics
    atomic64_set(&g_stats.total_events, 0);
    atomic64_set(&g_stats.total_dropped, 0);
    atomic64_set(&g_stats.total_sent, 0);
    atomic64_set(&g_stats.encrypt_failures, 0);
    atomic64_set(&g_stats.send_failures, 0);

    // initialize crypto subsystem
    ret = crypto_layer_init();
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to init crypto: %d\n", ret);
        goto cleanup_buffers;
    }

    // initialize cdev channel
    ret = cdev_channel_init();
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to init cdev: %d\n", ret);
        goto cleanup_crypto;
    }

    printk(KERN_INFO "[PHOTON RING] Event manager initialized\n");
    printk(KERN_INFO "[PHOTON RING] Buffer size per CPU: %d events\n", EVENT_BUFFER_SIZE);

    return 0;

cleanup_crypto:
    crypto_layer_exit();

cleanup_buffers:
    for_each_possible_cpu(cpu) {
        struct event_buffer *buf = &per_cpu(event_buffers, cpu);
        free_event_buffer(buf);
    }
    
    return ret;
}

void event_manager_exit(void)
{
    int cpu;
    
    printk(KERN_INFO "[PHOTON RING] Shutting down event manager...\n");
    
    // flush all pending events
    printk(KERN_INFO "[PHOTON RING] Flushing pending events...\n");
    flush_all_buffers();
    
    // print final statistics
    printk(KERN_INFO "[PHOTON RING] Event Statistics:\n");
    printk(KERN_INFO "[PHOTON RING]   Total events: %lld\n", 
           atomic64_read(&g_stats.total_events));
    printk(KERN_INFO "[PHOTON RING]   Sent: %lld\n", 
           atomic64_read(&g_stats.total_sent));
    printk(KERN_INFO "[PHOTON RING]   Dropped: %lld\n", 
           atomic64_read(&g_stats.total_dropped));
    printk(KERN_INFO "[PHOTON RING]   Send failures: %lld\n", 
           atomic64_read(&g_stats.send_failures));
    
    // cleanup cdev
    cdev_channel_exit();
    
    // cleanup crypto
    crypto_layer_exit();
    
    // free per-CPU buffers
    for_each_possible_cpu(cpu) {
        struct event_buffer *buf = &per_cpu(event_buffers, cpu);
        free_event_buffer(buf);
    }
    
    printk(KERN_INFO "[PHOTON RING] Event manager shut down\n");
}

int photon_log_event(u32 event_type, u32 detector_id, 
    const void *data, u16 data_len)
{
    struct photon_event event;
    int ret;

    // validate input
    if (data_len > PHOTON_MAX_EVENT_DATA) {
        printk(KERN_WARNING "[PHOTON RING] Event data too large: %u\n", data_len);
        return -EINVAL;
    }

    // build event structure
    memset(&event, 0, sizeof(event));
    event.sequence_num = atomic64_inc_return(&g_sequence_counter);
    event.timestamp_ns = ktime_get_real_ns();
    event.event_type = event_type;
    event.detector_id = detector_id;
    event.data_len = data_len;

    if (data && data_len > 0) {
        memcpy(event.data, data, data_len);
    }

    atomic64_inc(&g_stats.total_events);

    // enqueue to per-CPU buffer
    ret = enqueue_event(&event);
    if (ret) {
        // buffer full - try immediate flush and retry
        flush_all_buffers();
        ret = enqueue_event(&event);
        if (ret) {
            printk(KERN_WARNING "[PHOTON RING] Event queue full, dropping event\n");
            return ret;
        }
    }

    // flush immediately so every event reaches userspace without waiting
    // for a batch threshold — important for a security detection system
    flush_all_buffers();

    return 0;
}

u64 photon_get_sequence(void)
{
    return atomic64_read(&g_sequence_counter);
}

int photon_send_heartbeat(void)
{
    struct {
        u64 uptime_ns;
        u64 sequence_num;
        u64 events_sent;
        u64 events_dropped;
    } heartbeat_data;
    
    heartbeat_data.uptime_ns = ktime_get_ns();
    heartbeat_data.sequence_num = atomic64_read(&g_sequence_counter);
    heartbeat_data.events_sent = atomic64_read(&g_stats.total_sent);
    heartbeat_data.events_dropped = atomic64_read(&g_stats.total_dropped);
    
    return photon_log_event(PHOTON_EVENT_HEARTBEAT, 0, 
                           &heartbeat_data, sizeof(heartbeat_data));
}