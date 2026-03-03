// hook_stat_hiding.c
// Behavioral detector for stat-based hiding techniques

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dustin");
MODULE_DESCRIPTION("Detect stat-family syscall hiding behavior");
MODULE_VERSION("1.0");

#define MAX_TRACKED_PIDS 1024
#define FAILURE_THRESHOLD 10

/* ============================= */
/* Per-PID Failure Tracking      */
/* ============================= */

struct pid_stat_tracker {
    pid_t pid;
    int failure_count;
};

static struct pid_stat_tracker pid_table[MAX_TRACKED_PIDS];

/* ============================= */
/* Temporary Path Storage        */
/* ============================= */

#define MAX_PATH_LEN 256

struct stat_call_context {
    pid_t pid;
    char path[MAX_PATH_LEN];
};

static DEFINE_PER_CPU(struct stat_call_context, stat_ctx);

/* ============================= */
/* Utility Functions             */
/* ============================= */

static struct pid_stat_tracker *get_pid_tracker(pid_t pid)
{
    int i;
    for (i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (pid_table[i].pid == pid || pid_table[i].pid == 0) {
            pid_table[i].pid = pid;
            return &pid_table[i];
        }
    }
    return NULL;
}

static void log_event(const char *path, long ret)
{
    u64 ts = ktime_get_ns();
    const char *severity = "INFO";

    if (ret == -ENOENT)
        severity = "MEDIUM";

    printk(KERN_INFO
        "[PHOTON RING][%llu] PID:%d (%s) stat(%s) -> %ld [SEVERITY:%s]\n",
        ts,
        current->pid,
        current->comm,
        path,
        ret,
        severity);
}

/* ============================= */
/* ENTRY HOOK                    */
/* ============================= */

static void notrace hook_stat_entry(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
    const char __user *filename;
    struct stat_call_context *ctx;
    char kbuf[MAX_PATH_LEN];

    filename = (const char __user *)fregs->regs.di; // arg1 for x86_64

    if (!filename)
        return;

    if (strncpy_from_user(kbuf, filename, sizeof(kbuf)) <= 0)
        return;

    ctx = this_cpu_ptr(&stat_ctx);
    ctx->pid = current->pid;
    strlcpy(ctx->path, kbuf, MAX_PATH_LEN);
}

/* ============================= */
/* RETURN HOOK                   */
/* ============================= */

static void notrace hook_stat_return(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops,
                                     struct ftrace_regs *fregs)
{
    long ret = fregs->regs.ax; // return value
    struct stat_call_context *ctx = this_cpu_ptr(&stat_ctx);
    struct pid_stat_tracker *tracker;

    if (ctx->pid != current->pid)
        return;

    log_event(ctx->path, ret);

    /* Detect ENOENT anomaly */
    if (ret == -ENOENT) {

        tracker = get_pid_tracker(current->pid);
        if (!tracker)
            return;

        tracker->failure_count++;

        /* /proc anomaly detection */
        if (strstr(ctx->path, "/proc/")) {
            printk(KERN_ALERT
                "[PHOTON RING] HIGH: Suspicious /proc stat failure by PID %d (%s)\n",
                current->pid,
                current->comm);
        }

        /* Frequency anomaly detection */
        if (tracker->failure_count > FAILURE_THRESHOLD) {
            printk(KERN_ALERT
                "[PHOTON RING] HIGH: Excessive stat failures by PID %d (%s)\n",
                current->pid,
                current->comm);
        }
    }
}

/* ============================= */
/* FTRACE OPS                    */
/* ============================= */

static struct ftrace_ops entry_ops = {
    .func = hook_stat_entry,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE,
};

static struct ftrace_ops return_ops = {
    .func = hook_stat_return,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE,
};

/* ============================= */
/* INIT                          */
/* ============================= */

static int __init hiding_stat_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] Loading stat hiding detector...\n");

    ret = ftrace_set_filter(&entry_ops, "__x64_sys_newfstatat", 0, 0);
    if (ret)
        return ret;

    ret = register_ftrace_function(&entry_ops);
    if (ret)
        return ret;

    ret = ftrace_set_filter(&return_ops, "__x64_sys_newfstatat", 0, 0);
    if (ret)
        return ret;

    ret = register_ftrace_function(&return_ops);
    if (ret)
        return ret;

    printk(KERN_INFO "[PHOTON RING] Stat detector active.\n");
    return 0;
}

/* ============================= */
/* EXIT                          */
/* ============================= */

static void __exit hiding_stat_exit(void)
{
    unregister_ftrace_function(&entry_ops);
    unregister_ftrace_function(&return_ops);

    printk(KERN_INFO "[PHOTON RING] Stat detector unloaded.\n");
}

module_init(hiding_stat_init);
module_exit(hiding_stat_exit);