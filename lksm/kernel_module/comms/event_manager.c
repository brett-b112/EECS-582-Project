/*
 * event_manager.c — Photon Ring
 *
 * Central event pipeline: per-CPU ring buffers → per-CPU flush kthreads →
 * AES-GCM encryption → cdev output ring → userspace read().
 *
 * Architecture overview — hybrid fast/slow path
 * -----------------------------------------------
 *
 *  Detector (any CPU, any context)
 *       │
 *       ▼  photon_log_event()
 *       │
 *       ├─ sleepable context + key ready?
 *       │       │
 *       │       ▼  FAST PATH  (~500 ns, no context switch)
 *       │  photon_send_encrypted_event()
 *       │  (per-CPU workspace, per-CPU AES-GCM transform, no lock)
 *       │       │
 *       │       ▼
 *       │  cdev output ring  →  userspace read()
 *       │
 *       └─ atomic context OR key not yet set?
 *               │
 *               ▼  SLOW PATH  (spinlock + memcpy, then scheduler wakeup)
 *          Per-CPU ring buffer
 *               │
 *               ▼  per-CPU flush kthread (woken by wake_up_interruptible)
 *          photon_send_encrypted_event()
 *               │
 *               ▼
 *          cdev output ring  →  userspace read()
 *
 * Fast path vs slow path
 * ----------------------
 * The slow path (enqueue → kthread wakeup → encrypt) introduced ~100–800 µs
 * of scheduler wakeup latency as the dominant cost.  The fast path eliminates
 * that entirely by encrypting and sending inline on the calling CPU when two
 * conditions hold:
 *
 *   1. !in_atomic() && !irqs_disabled()
 *      The calling context is sleepable (task context).  It is safe to call
 *      kmalloc(GFP_KERNEL) and crypto_aead_encrypt(), both of which may
 *      schedule internally.  This covers the majority of detector calls:
 *      kprobe hooks fire in the context of the process that called
 *      register_kprobe; ftrace hooks on commit_creds fire in the context of
 *      the process changing credentials; kallsyms hooks fire in task context.
 *
 *   2. photon_has_key()
 *      The AES-GCM transforms have been keyed.  Before the master key
 *      arrives from userspace, events must be buffered rather than dropped,
 *      so the slow path is always used until the key is installed.
 *
 * If the fast-path encrypt fails (e.g. output ring full), the event falls
 * through to the slow path so it is buffered and retried by the flush thread
 * rather than silently dropped.
 *
 * The slow path remains correct and necessary for:
 *   - Ftrace callbacks with FTRACE_OPS_FL_SAVE_REGS (preempt disabled →
 *     in_atomic() is true).
 *   - Any other atomic/IRQ context detector.
 *   - Pre-key events that must be buffered until the key arrives.
 *   - Fast-path encrypt failures.
 *
 * Key design decisions
 * --------------------
 *
 * 1. Per-CPU flush threads.  The original single flush thread drained all
 *    CPUs serially.  On an N-core machine, N-1 CPUs' buffers sat untouched
 *    while CPU 0 was being drained.  Now each CPU has its own kthread
 *    (photon_flush/<cpu>) pinned via kthread_bind().  Encryption is fully
 *    parallel across all CPUs — each thread uses its own crypto_aead
 *    transform (see crypto.c) so there is no shared lock on the encrypt path.
 *
 * 2. g_em_active shutdown guard.  Detectors call photon_log_event() and are
 *    stopped *after* event_manager_exit() runs.  Without a guard, a detector
 *    firing during its own teardown could enqueue into a freed buffer.
 *    g_em_active is set to false before any buffer is freed; photon_log_event
 *    returns -ESHUTDOWN immediately once it sees false.
 *
 * 3. Rate-limited drop warning.  A flood of detections previously caused a
 *    secondary dmesg flood from the drop-path printk.  Now it uses
 *    printk_ratelimited so at most one message per second reaches the log.
 *
 * 4. Per-CPU pending flag.  Instead of one global g_pending_events counter
 *    shared by all CPUs (requiring an atomic_inc on every enqueue and an
 *    atomic_read on every wake check), each CPU has its own atomic_t.  The
 *    flush thread for that CPU only watches its own flag.
 */
 
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>     /* sched_set_fifo()                          */
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/preempt.h>  /* in_atomic()      */
#include <linux/irqflags.h> /* irqs_disabled()  */
#include "event_manager.h"
#include "cdev_ch.h"
#include "crypto.h"
 
/*
 * PHOTON_FLUSH_RT_PRIO — SCHED_FIFO priority for flush kthreads.
 *
 * Priority 50 sits above all normal (SCHED_NORMAL / SCHED_OTHER) tasks
 * and above most system threads, but below hard-RT work (typically 90+)
 * and below the watchdog/migration threads (99).  This ensures a flush
 * kthread is scheduled within one scheduling quantum (~100 µs) of being
 * woken on any reasonably loaded system, replacing the 100-800 µs wakeup
 * latency observed with SCHED_NORMAL.
 *
 * Range: 1 (lowest RT) – 99 (highest RT, reserved for kernel internals).
 */
#define PHOTON_FLUSH_RT_PRIO  50
 
/* global sequence counter — monotonically increasing across all CPUs */
static atomic64_t g_sequence_counter = ATOMIC64_INIT(0);
 
/*
 * g_em_active — set to true in event_manager_init() before any detector
 * runs, cleared to false at the very start of event_manager_exit() before
 * any buffer is freed.  photon_log_event() returns -ESHUTDOWN immediately
 * when false, preventing use-after-free if a detector fires during its own
 * teardown.
 */
static atomic_t g_em_active = ATOMIC_INIT(0);
 
/* -------------------------------------------------------------------------
 * Per-CPU event ring buffer
 * -------------------------------------------------------------------------*/
#define EVENT_BUFFER_SIZE 64    /* slots per CPU; handoff queue only */
 
struct event_buffer {
    spinlock_t          lock;
    struct photon_event *events;
    u32                 head;
    u32                 tail;
    u32                 capacity;
    u32                 dropped;
};
 
static DEFINE_PER_CPU(struct event_buffer, event_buffers);
 
/* -------------------------------------------------------------------------
 * Per-CPU flush kthread state
 *
 * Each online CPU gets one kthread pinned to it.  The kthread pointer and
 * its private wait queue are stored per-CPU.
 *
 * We use a per-CPU wait queue head rather than one global one so that
 * wake_up only disturbs the specific CPU's flush thread, not all of them.
 * -------------------------------------------------------------------------*/
static DEFINE_PER_CPU(struct task_struct *,    flush_thread);
static DEFINE_PER_CPU(wait_queue_head_t,       flush_wq);
static DEFINE_PER_CPU(atomic_t,                pending_events);
 
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
 
static inline bool buffer_is_full(const struct event_buffer *buf)
{
    return ((buf->head + 1) % buf->capacity) == buf->tail;
}
 
static inline bool buffer_is_empty(const struct event_buffer *buf)
{
    return buf->head == buf->tail;
}
 
/* -------------------------------------------------------------------------
 * enqueue_event
 *
 * Hot path — called from any context (atomic, IRQ, softirq, task).
 * Touches only a per-CPU spinlock and a memcpy.  No allocation, no sleeping.
 * -------------------------------------------------------------------------*/
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
    } else {
        memcpy(&buf->events[buf->head], event, sizeof(struct photon_event));
        buf->head = (buf->head + 1) % buf->capacity;
    }
 
    spin_unlock_irqrestore(&buf->lock, flags);
    put_cpu_var(event_buffers);
    return ret;
}
 
/* -------------------------------------------------------------------------
 * flush_event_buffer
 *
 * Drain one CPU's ring buffer, encrypting and sending each event.
 * Called only from that CPU's flush kthread (sleepable context).
 * The spinlock is dropped around the encrypt+send so the enqueue path is
 * never blocked by I/O.
 * -------------------------------------------------------------------------*/
static void flush_event_buffer(struct event_buffer *buf)
{
    unsigned long flags;
    struct photon_event event;
    int ret;
 
    spin_lock_irqsave(&buf->lock, flags);
 
    while (!buffer_is_empty(buf)) {
        memcpy(&event, &buf->events[buf->tail], sizeof(struct photon_event));
        buf->tail = (buf->tail + 1) % buf->capacity;
 
        /* Drop the lock around the expensive encrypt+send */
        spin_unlock_irqrestore(&buf->lock, flags);
 
        ret = photon_send_encrypted_event(&event);
        if (ret) {
            atomic64_inc(&g_stats.send_failures);
            printk_ratelimited(KERN_WARNING
                "[PHOTON RING] Failed to send event: %d\n", ret);
        } else {
            atomic64_inc(&g_stats.total_sent);
        }
 
        spin_lock_irqsave(&buf->lock, flags);
    }
 
    spin_unlock_irqrestore(&buf->lock, flags);
}
 
/* -------------------------------------------------------------------------
 * Per-CPU flush kthread body
 *
 * Each instance is pinned to one CPU via kthread_bind() so it always drains
 * the same CPU's buffer and always uses that CPU's AES-GCM transform.
 * -------------------------------------------------------------------------*/
static int flush_thread_fn(void *cpu_ptr)
{
    int cpu = (int)(long)cpu_ptr;
    struct event_buffer *buf  = &per_cpu(event_buffers, cpu);
    wait_queue_head_t   *wq   = &per_cpu(flush_wq,      cpu);
    atomic_t            *pend = &per_cpu(pending_events, cpu);
 
    while (!kthread_should_stop()) {
        /*
         * Sleep until this CPU has pending events, or until we are being
         * stopped.  Using wait_event_interruptible lets a stray signal wake
         * us; we simply loop back and check kthread_should_stop().
         */
        wait_event_interruptible(*wq,
            atomic_read(pend) > 0 || kthread_should_stop());
 
        if (kthread_should_stop())
            break;
 
        /*
         * Clear the flag before draining.  If new events arrive during the
         * drain they will set the flag again and we loop immediately.
         */
        atomic_set(pend, 0);
 
        /* Hold off if key not yet available — events stay buffered */
        if (!photon_has_key())
            continue;
 
        flush_event_buffer(buf);
    }
 
    /* Final drain on stop (clean rmmod path) */
    if (photon_has_key())
        flush_event_buffer(buf);
 
    return 0;
}
 
/* -------------------------------------------------------------------------
 * build_event — fill a photon_event envelope on the caller's stack.
 *
 * Separated from photon_log_event so it is called exactly once regardless
 * of which path (fast or slow) handles the event.
 * -------------------------------------------------------------------------*/
static void build_event(struct photon_event *event,
                        u32 event_type, u32 detector_id, u8 severity,
                        const void *data, u16 data_len)
{
    memset(event, 0, sizeof(*event));
    event->sequence_num = atomic64_inc_return(&g_sequence_counter);
    event->timestamp_ns = ktime_get_real_ns();
    event->event_type   = event_type;
    event->detector_id  = detector_id;
    event->severity     = severity;
    event->caller_pid   = (u32)current->pid;
    strncpy(event->caller_comm, current->comm,
            sizeof(event->caller_comm) - 1);
    event->data_len = data_len;
    if (data && data_len > 0)
        memcpy(event->data, data, data_len);
    event->dispatch_ts = ktime_get_real_ns();
}
 
/* -------------------------------------------------------------------------
 * enqueue_and_wake — slow path: buffer the event and wake the flush thread.
 *
 * Used when the caller is in atomic context (preempt disabled, IRQ, etc.)
 * or when the key is not yet installed.  The flush kthread will encrypt and
 * deliver the event once it is scheduled.
 * -------------------------------------------------------------------------*/
static int enqueue_and_wake(struct photon_event *event)
{
    int cpu, ret;
 
    ret = enqueue_event(event);
    if (ret) {
        printk_ratelimited(KERN_WARNING
            "[PHOTON RING] Per-CPU buffer full, dropping event "
            "(type=%u sev=%u)\n", event->event_type, event->severity);
        return ret;
    }
 
    /*
     * Wake only this CPU's flush thread.  get_cpu()/put_cpu() pins us long
     * enough to read the correct per-CPU pointers; we do not need to stay
     * pinned across the wake_up call itself.
     */
    cpu = get_cpu();
    atomic_inc(&per_cpu(pending_events, cpu));
    wake_up_interruptible(&per_cpu(flush_wq, cpu));
    put_cpu();
 
    return 0;
}
 
/* -------------------------------------------------------------------------
 * photon_log_event — public API, called by all detectors
 *
 * Safe to call from ANY kernel context: ftrace hooks, kprobe handlers,
 * IRQ handlers, softirqs, normal task context.
 *
 * FAST PATH — used when both of the following hold:
 *   (a) photon_has_key(): the per-CPU AES-GCM transforms are keyed and
 *       ready.  Without a key there is nothing to encrypt with, so events
 *       must be buffered until the key arrives via ioctl.
 *   (b) !in_atomic() && !irqs_disabled(): the calling context is sleepable.
 *       crypto_aead_encrypt() and kmalloc(GFP_KERNEL) may reschedule; they
 *       must not be called with preemption disabled or from IRQ context.
 *
 *   On the fast path the event is encrypted and handed to the cdev ring
 *   inline, on the calling CPU, without any context switch.  This eliminates
 *   the 100–800 µs scheduler wakeup latency that dominated the slow path.
 *
 *   If the fast-path send fails (e.g. the output ring is momentarily full),
 *   the event falls through to the slow path so it is buffered and retried
 *   by the flush thread rather than silently dropped.
 *
 * SLOW PATH — used when the key is not set, or the caller is in atomic
 *   context.  The event is copied into the per-CPU ring buffer under a
 *   spinlock, and that CPU's flush kthread is woken to drain it.
 *
 * The fast path covers the majority of detector calls:
 *   - kprobe hooks fire in the context of the process calling register_kprobe
 *   - ftrace hooks on commit_creds fire in the context of the escalating task
 *   - kallsyms hooks fire in the context of the process doing the lookup
 *
 * The slow path handles the minority that arrive in constrained contexts:
 *   - ftrace callbacks with SAVE_REGS active (preempt disabled)
 *   - any future detector running from IRQ/softirq context
 * -------------------------------------------------------------------------*/
int photon_log_event(u32 event_type, u32 detector_id, u8 severity,
                     const void *data, u16 data_len)
{
    struct photon_event event;
    int ret;
 
    /* Shutdown guard: reject immediately if the manager is tearing down */
    if (!atomic_read(&g_em_active))
        return -ESHUTDOWN;
 
    if (data_len > PHOTON_MAX_EVENT_DATA) {
        printk_ratelimited(KERN_WARNING
            "[PHOTON RING] Event data too large: %u (max %u)\n",
            data_len, PHOTON_MAX_EVENT_DATA);
        return -EINVAL;
    }
 
    build_event(&event, event_type, detector_id, severity, data, data_len);
    atomic64_inc(&g_stats.total_events);
 
    /*
     * FAST PATH: encrypt and send inline, no context switch.
     *
     * in_atomic() is true when:
     *   - preempt_count > 0  (preemption disabled, spinlock held, etc.)
     *   - in_interrupt()     (hard IRQ or softirq)
     *
     * irqs_disabled() catches the case where interrupts are off but
     * preempt_count has not been incremented (rare but possible in some
     * low-level paths).
     *
     * Both conditions mean we cannot sleep, so we cannot call GFP_KERNEL
     * allocators or the crypto API.  Use the slow path instead.
     */
    if (photon_has_key() && !in_atomic() && !irqs_disabled()) {
        ret = photon_send_encrypted_event(&event);
        if (ret == 0) {
            atomic64_inc(&g_stats.total_sent);
            return 0;
        }
        /*
         * Fast-path send failed (most likely the output ring is full).
         * Fall through to the slow path so the event is buffered and
         * retried rather than dropped.
         *
         * Do NOT return here — let enqueue_and_wake() run below.
         */
    }
 
    /* SLOW PATH: enqueue into the per-CPU ring and wake the flush thread */
    return enqueue_and_wake(&event);
}
 
/* -------------------------------------------------------------------------
 * photon_flush_pending - wake all flush threads
 *
 * Called after out-of-band state changes (key set, key rotation) that make
 * previously undeliverable buffered events deliverable.
 * -------------------------------------------------------------------------*/
void photon_flush_pending(void)
{
    int cpu;
 
    for_each_possible_cpu(cpu) {
        struct task_struct *t = per_cpu(flush_thread, cpu);
        if (!t)
            continue;
        atomic_inc(&per_cpu(pending_events, cpu));
        wake_up_interruptible(&per_cpu(flush_wq, cpu));
    }
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
    hb.new_rotation_num = 0;
 
    return photon_log_event(PHOTON_EVENT_SYSTEM_HEARTBEAT, 0,
                            PHOTON_SEV_INFO, &hb, sizeof(hb));
}
 
/* -------------------------------------------------------------------------
 * event_manager_init
 * -------------------------------------------------------------------------*/
int event_manager_init(void)
{
    int cpu, ret;
 
    printk(KERN_INFO "[PHOTON RING] Initializing event manager...\n");
 
    /* Initialize per-CPU structures before marking the manager active */
    for_each_possible_cpu(cpu) {
        struct event_buffer *buf = &per_cpu(event_buffers, cpu);
 
        ret = init_event_buffer(buf);
        if (ret) {
            printk(KERN_ERR
                   "[PHOTON RING] Failed to init buffer for CPU %d: %d\n",
                   cpu, ret);
            goto cleanup_buffers;
        }
 
        init_waitqueue_head(&per_cpu(flush_wq, cpu));
        atomic_set(&per_cpu(pending_events, cpu), 0);
        per_cpu(flush_thread, cpu) = NULL;
    }
 
    atomic64_set(&g_stats.total_events,  0);
    atomic64_set(&g_stats.total_dropped, 0);
    atomic64_set(&g_stats.total_sent,    0);
    atomic64_set(&g_stats.send_failures, 0);
 
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
 
    /*
     * Mark the manager active before starting threads so that any event
     * logged by the threads themselves passes the shutdown guard.
     */
    atomic_set(&g_em_active, 1);
 
    /*
     * Start one flush kthread per possible CPU, pinned via kthread_bind().
     * Possible (not online) CPUs are included so that CPU hotplug events
     * that bring a CPU online after module load still have a ready thread.
     * kthread_bind() parks the thread until the CPU comes online.
     *
     * Each thread is elevated to SCHED_FIFO at PHOTON_FLUSH_RT_PRIO before
     * being woken.  This cuts slow-path wakeup latency from 100-800 µs
     * (SCHED_NORMAL, competing with all user tasks) to under 20 µs
     * (SCHED_FIFO, preempts any lower-priority work the moment it's ready).
     * The thread only runs when there are buffered events to drain, so the
     * RT priority does not starve normal workloads.
     */
    for_each_possible_cpu(cpu) {
        struct task_struct  *t;
 
        t = kthread_create(flush_thread_fn, (void *)(long)cpu,
                           "photon_flush/%d", cpu);
        if (IS_ERR(t)) {
            ret = PTR_ERR(t);
            printk(KERN_ERR
                   "[PHOTON RING] Failed to create flush thread for CPU %d: %d\n",
                   cpu, ret);
            goto cleanup_threads;
        }
 
        kthread_bind(t, cpu);
 
        /*
         * sched_set_fifo() is EXPORT_SYMBOL_GPL since 5.9 and is the
         * correct module-facing API for elevating a kthread to SCHED_FIFO.
         * It sets priority 50 internally and skips the permission check,
         * which is correct for trusted kernel threads.  It must be called
         * before wake_up_process() so the thread is already at RT priority
         * the first time the scheduler considers running it.
         */
        sched_set_fifo(t);
 
        per_cpu(flush_thread, cpu) = t;
        wake_up_process(t);
    }
 
    printk(KERN_INFO "[PHOTON RING] Event manager initialized — "
           "%d flush thread(s) at SCHED_FIFO prio %d, "
           "%d slot buffer per CPU, max payload %d B\n",
           num_possible_cpus(), PHOTON_FLUSH_RT_PRIO,
           EVENT_BUFFER_SIZE, PHOTON_MAX_EVENT_DATA);
    return 0;
 
cleanup_threads:
    /* Stop any threads that were successfully started */
    for_each_possible_cpu(cpu) {
        struct task_struct *t = per_cpu(flush_thread, cpu);
        if (t) {
            kthread_stop(t);
            per_cpu(flush_thread, cpu) = NULL;
        }
    }
    atomic_set(&g_em_active, 0);
    cdev_channel_exit();
cleanup_crypto:
    crypto_layer_exit();
cleanup_buffers:
    for_each_possible_cpu(cpu)
        free_event_buffer(&per_cpu(event_buffers, cpu));
    return ret;
}
 
/* -------------------------------------------------------------------------
 * event_manager_exit
 * -------------------------------------------------------------------------*/
void event_manager_exit(void)
{
    int cpu;
 
    printk(KERN_INFO "[PHOTON RING] Shutting down event manager...\n");
 
    /*
     * Disable the fast path first.  Any detector that fires after this
     * point (during its own teardown) gets -ESHUTDOWN from photon_log_event
     * and does nothing.  Buffers are still intact at this point.
     */
    atomic_set(&g_em_active, 0);
 
    /*
     * Stop all flush threads.  kthread_stop() sets kthread_should_stop()
     * and blocks until each thread exits.  Each thread does a final
     * flush_event_buffer() before returning.
     */
    for_each_possible_cpu(cpu) {
        struct task_struct *t = per_cpu(flush_thread, cpu);
        if (t) {
            /*
             * Wake the thread in case it is sleeping — kthread_stop alone
             * does not unblock wait_event_interruptible.
             */
            atomic_inc(&per_cpu(pending_events, cpu));
            wake_up_interruptible(&per_cpu(flush_wq, cpu));
 
            kthread_stop(t);
            per_cpu(flush_thread, cpu) = NULL;
        }
    }
 
    printk(KERN_INFO "[PHOTON RING] Event statistics:\n");
    printk(KERN_INFO "[PHOTON RING]   Total:         %lld\n",
           atomic64_read(&g_stats.total_events));
    printk(KERN_INFO "[PHOTON RING]   Sent:          %lld\n",
           atomic64_read(&g_stats.total_sent));
    printk(KERN_INFO "[PHOTON RING]   Dropped:       %lld\n",
           atomic64_read(&g_stats.total_dropped));
    printk(KERN_INFO "[PHOTON RING]   Send failures: %lld\n",
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