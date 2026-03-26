// reset_tainted_detector.c
// Detects rootkits that clear kernel taint flags and spawn hidden kernel threads.
//
// Targeted rootkit pattern ("zer0t" / reset_tainted module):
//   1. Resolves tainted_mask via kallsyms_lookup_name
//   2. Spawns a kernel thread named "zer0t" via kthread_run
//   3. Thread sets *tainted_mask = 0, erasing all kernel taint flags
//   4. Hides the thread's PID via add_hidden_pid()
//
// Detection vectors:
//   A. ftrace hook on kthread_create_on_node:
//      Fires at thread creation time; alerts on known-suspicious names.
//
//   B. Periodic workqueue (every 5s): reads tainted_mask directly and
//      alerts when previously-set taint bits are cleared to 0.
//
//   C. Periodic task list scan (every 10s): walks init_task.tasks
//      (the full kernel task list) to find threads with suspicious names
//      that may be hidden from /proc via add_hidden_pid().

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include "../include/photon_ring_arch.h"
#include "../include/reset_tainted_detector.h"

/* -----------------------------------------------------------------------
 * Shared state
 * ----------------------------------------------------------------------- */

/* Signals to workqueue callbacks that the module is unloading */
static bool detector_exiting;

/* Thread names used by known taint-clearing rootkits */
static const char * const suspicious_names[] = {
    "zer0t",
    NULL /* sentinel */
};

/* -----------------------------------------------------------------------
 * kallsyms_lookup_name resolution (kprobe trick)
 *
 * tainted_mask is a data symbol and cannot be reached via register_kprobe
 * (which only works on code).  We use the kprobe trick to get the address
 * of kallsyms_lookup_name itself, then call it to resolve tainted_mask.
 *
 * This detector is placed first in the main.c registry so this kprobe
 * fires before kprobe_detector is active, avoiding a false-positive alert.
 * ----------------------------------------------------------------------- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t photon_kallsyms_lookup;

static int resolve_kallsyms_lookup_name(void)
{
    struct kprobe kp;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kp) < 0)
        return -ENOENT;
    photon_kallsyms_lookup = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

/* -----------------------------------------------------------------------
 * Vector A: ftrace hook on kthread_create_on_node
 * -----------------------------------------------------------------------
 * kthread_run(fn, data, namefmt) expands to kthread_create_on_node, which
 * takes:
 *   arg0 = threadfn   (function pointer)
 *   arg1 = data
 *   arg2 = node       (int — NUMA node)
 *   arg3 = namefmt    (const char * — thread name format string)
 *
 * The rootkit calls kthread_run(zt_thread, NULL, "zer0t"), so namefmt is
 * the literal string "zer0t" with no format specifiers.
 * ----------------------------------------------------------------------- */
static struct ftrace_ops kthread_ops;
static bool kthread_hook_active;

static notrace void hook_kthread_create(unsigned long ip,
                                        unsigned long parent_ip,
                                        struct ftrace_ops *ops,
                                        struct ftrace_regs *fregs)
{
    const char *namefmt;
    int i;

    namefmt = (const char *)PHOTON_RING_GET_ARG(fregs, 3);
    if (!namefmt)
        return;

    for (i = 0; suspicious_names[i]; i++) {
        if (strcmp(namefmt, suspicious_names[i]) == 0) {
            printk(KERN_ALERT
                   "[PHOTON RING] SUSPICIOUS *** kthread '%s' spawned!"
                   " Caller: %pS, process: '%s' (PID %d)."
                   " Possible taint-clearing rootkit!\n",
                   namefmt, (void *)parent_ip,
                   current->comm, current->pid);
            return;
        }
    }
}

static int setup_kthread_hook(void)
{
    /* kthread_create_on_node is an exported symbol — no kallsyms needed */
    unsigned long addr = (unsigned long)kthread_create_on_node;
    int ret;

    kthread_ops.func  = hook_kthread_create;
    kthread_ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&kthread_ops, addr, 0, 0);
    if (ret) {
        printk(KERN_WARNING "[PHOTON RING] reset_tainted: "
               "ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&kthread_ops);
    if (ret) {
        printk(KERN_WARNING "[PHOTON RING] reset_tainted: "
               "register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&kthread_ops, addr, 1, 0);
        return ret;
    }

    kthread_hook_active = true;
    printk(KERN_INFO "[PHOTON RING] reset_tainted: "
           "kthread_create_on_node hook active at 0x%lx\n", addr);
    return 0;
}

static void teardown_kthread_hook(void)
{
    if (!kthread_hook_active)
        return;
    unregister_ftrace_function(&kthread_ops);
    ftrace_set_filter_ip(&kthread_ops,
                         (unsigned long)kthread_create_on_node, 1, 0);
    kthread_hook_active = false;
}

/* -----------------------------------------------------------------------
 * Vector B: Periodic tainted_mask monitoring
 *
 * We resolve tainted_mask via kallsyms_lookup_name (a data symbol, not
 * probeable with kprobes directly), record the initial value, and poll
 * every 5 seconds.  If any previously-set bits are cleared — especially
 * all bits cleared to 0 — that is the exact behaviour of the rootkit.
 * ----------------------------------------------------------------------- */
static unsigned long *tainted_mask_ptr;
static unsigned long taint_baseline;
static struct delayed_work taint_check_work;

static void taint_check_fn(struct work_struct *work)
{
    unsigned long cur;
    unsigned long cleared;

    cur     = READ_ONCE(*tainted_mask_ptr);
    cleared = taint_baseline & ~cur;

    if (cleared != 0) {
        printk(KERN_ALERT
               "[PHOTON RING] SUSPICIOUS *** tainted_mask cleared!"
               " Cleared bits: 0x%lx (was: 0x%lx, now: 0x%lx)."
               " Possible rootkit taint erasure (reset_tainted / zer0t)!\n",
               cleared, taint_baseline, cur);
        /* Update baseline so we don't spam repeated alerts */
        taint_baseline = cur;
    }

    if (!READ_ONCE(detector_exiting))
        schedule_delayed_work(&taint_check_work, 5 * HZ);
}

static void setup_taint_poll(void)
{
    unsigned long addr;

    if (!photon_kallsyms_lookup) {
        printk(KERN_WARNING "[PHOTON RING] reset_tainted: "
               "kallsyms_lookup_name unavailable, skipping taint polling\n");
        return;
    }

    addr = photon_kallsyms_lookup("tainted_mask");
    if (!addr) {
        printk(KERN_WARNING "[PHOTON RING] reset_tainted: "
               "tainted_mask not found, skipping taint polling\n");
        return;
    }

    tainted_mask_ptr = (unsigned long *)addr;
    taint_baseline   = READ_ONCE(*tainted_mask_ptr);

    printk(KERN_INFO "[PHOTON RING] reset_tainted: "
           "tainted_mask at %p, baseline=0x%lx\n",
           tainted_mask_ptr, taint_baseline);

    if (taint_baseline == 0)
        printk(KERN_WARNING "[PHOTON RING] reset_tainted: "
               "taint baseline is 0 — rootkit may have already cleared it,"
               " or kernel is genuinely untainted\n");

    schedule_delayed_work(&taint_check_work, 5 * HZ);
}

/* -----------------------------------------------------------------------
 * Vector C: Periodic kernel task list scan
 *
 * The rootkit hides the "zer0t" kthread from /proc via add_hidden_pid(),
 * but the task_struct remains on init_task.tasks.  We walk the list under
 * RCU and alert on any task whose comm matches a suspicious name.
 * ----------------------------------------------------------------------- */
static struct delayed_work thread_scan_work;

static void thread_scan_fn(struct work_struct *work)
{
    struct task_struct *task;
    int i;

    rcu_read_lock();
    for_each_process(task) {
        for (i = 0; suspicious_names[i]; i++) {
            if (strcmp(task->comm, suspicious_names[i]) == 0) {
                printk(KERN_ALERT
                       "[PHOTON RING] SUSPICIOUS *** suspicious task found"
                       " in kernel task list: '%s' (PID %d, TGID %d)."
                       " Possible hidden rootkit thread!\n",
                       task->comm, task->pid, task->tgid);
            }
        }
    }
    rcu_read_unlock();

    if (!READ_ONCE(detector_exiting))
        schedule_delayed_work(&thread_scan_work, 10 * HZ);
}

/* -----------------------------------------------------------------------
 * Init / Exit
 * ----------------------------------------------------------------------- */

int __init reset_tainted_detector_init(void)
{
    printk(KERN_INFO "[PHOTON RING] Initializing reset_tainted detector...\n");

    /*
     * Always initialize work structs first so that exit() can safely call
     * cancel_delayed_work_sync() regardless of how far init progressed.
     */
    INIT_DELAYED_WORK(&taint_check_work, taint_check_fn);
    INIT_DELAYED_WORK(&thread_scan_work, thread_scan_fn);

    /* Resolve kallsyms_lookup_name for data symbol access (Vector B) */
    if (resolve_kallsyms_lookup_name() < 0)
        printk(KERN_WARNING "[PHOTON RING] reset_tainted: "
               "kallsyms_lookup_name resolution failed\n");

    /* Vector A: kthread creation hook */
    setup_kthread_hook();

    /* Vector B: tainted_mask polling */
    setup_taint_poll();

    /* Vector C: task list scan — first scan after 2s, then every 10s */
    schedule_delayed_work(&thread_scan_work, 2 * HZ);

    printk(KERN_INFO "[PHOTON RING] reset_tainted detector active"
           " (3 vectors: kthread hook, taint poll, task scan)\n");
    return 0;
}

void __exit reset_tainted_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] Removing reset_tainted detector...\n");

    /*
     * Signal workqueues to stop re-scheduling, then wait for any
     * currently-running work to complete before unloading.
     */
    WRITE_ONCE(detector_exiting, true);
    teardown_kthread_hook();
    cancel_delayed_work_sync(&taint_check_work);
    cancel_delayed_work_sync(&thread_scan_work);

    printk(KERN_INFO "[PHOTON RING] reset_tainted detector removed\n");
}
