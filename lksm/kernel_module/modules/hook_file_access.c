#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>   // pt_regs layout for x86_64 / arm64

#include "../include/hook_file_access.h"

/*
 * Use a kretprobe on do_filp_open so it can:
 *  - grab flags/mode on entry
 *  - grab struct file * return value on exit (reason for using kretprobe)
 *  - resolve absolute path using d_path(file->f_path) 
 *
 * Safer than trying to resolve absolute paths from a user pointer with ftrace
 */

#define MAX_PATH_BUF  512

/*
 * kretprobe portability shim for pt_regs
 * Same utility as photon_ring_arch.h but for kretprobe
 * -------------------------------------
 * kretprobe returns a struct pt_regs*, so helpers are provided
 * for x86_64 and arm64.
 */
static __always_inline unsigned long pr_get_arg(struct pt_regs *regs, int n)
{
#if defined(__x86_64__)
    switch (n) {
        case 0: return regs->di;
        case 1: return regs->si;
        case 2: return regs->dx;
        case 3: return regs->cx;
        case 4: return regs->r8;
        case 5: return regs->r9;
        default: return 0;
    }
#elif defined(__aarch64__)
    /* arm64 AAPCS64: args in regs[0..7] */
    if (n >= 0 && n < 8)
        return regs->regs[n];
    return 0;
#else
#warning "Photon Ring: pr_get_arg() unsupported architecture"
    (void)regs; (void)n;
    return 0;
#endif
}

static __always_inline unsigned long pr_get_ret(struct pt_regs *regs)
{
#if defined(__x86_64__)
    return regs->ax;
#elif defined(__aarch64__)
    /* arm64 return value in x0 => regs[0] */
    return regs->regs[0];
#else
#warning "Photon Ring: pr_get_ret() unsupported architecture"
    (void)regs;
    return 0;
#endif
}

// Simple sensitive targets (expand later)
static const char *sensitive_exact[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
};

static const char *sensitive_prefix[] = {
    "/etc/ssh/",
    "/home/",      // Check for "/.ssh/" inside
    "/root/.ssh/",
};

// Data stored for each do_filp_open call upon function call
struct open_call_ctx {
    u64 ts_ns;
    pid_t pid;
    pid_t ppid;
    kuid_t kuid;
    kgid_t kgid;
    char comm[TASK_COMM_LEN];

    // best-effort flags/mode capture (depends on kernel signature)
    unsigned long flags;
    umode_t mode;
};

static bool is_sensitive_path(const char *path)
{
    int i;

    // Exact matches
    for (i = 0; i < ARRAY_SIZE(sensitive_exact); i++) {
        if (strcmp(path, sensitive_exact[i]) == 0)
            return true;
    }

    // Prefix matches + "~/.ssh" pattern
    for (i = 0; i < ARRAY_SIZE(sensitive_prefix); i++) {
        if (strncmp(path, sensitive_prefix[i], strlen(sensitive_prefix[i])) == 0) {
            // If it’s under /home/, only treat as sensitive if it contains "/.ssh/"
            if (strcmp(sensitive_prefix[i], "/home/") == 0) {
                if (strstr(path, "/.ssh/") != NULL)
                    return true;
                continue;
            }
            return true;
        }
    }

    return false;
}

static bool is_writeish(unsigned long flags)
{
    // Open flag bits are user-space O_* values
    // Treat any write/create/truncate/append as suspicious "write-ish" behavior
    return (flags & O_WRONLY) ||
           (flags & O_RDWR)   ||
           (flags & O_APPEND) ||
           (flags & O_TRUNC)  ||
           (flags & O_CREAT);
}

/*
 * Entry handler: capture process context + attempt to capture open flags/mode.
 *
 * NOTE: do_filp_open signature can vary by kernel.
 * For modern kernels, it's usually:
 *   do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
 *
 * Best-effort:
 *   arg2 may point to open_flags; it tries to read flags/mode from it
 * If this fails, it still logs path + process context from the return handler.
 */
static int do_filp_open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct open_call_ctx *ctx = (struct open_call_ctx *)ri->data;

    ctx->ts_ns = ktime_get_ns();
    ctx->pid = current->pid;
    ctx->ppid = current->real_parent ? current->real_parent->pid : -1;
    ctx->kuid = current_uid();
    ctx->kgid = current_gid();
    get_task_comm(ctx->comm, current);

    ctx->flags = 0;
    ctx->mode = 0;

    /*
     * Best effort: third arg may be open_flags*
     * Use pr_get_arg(regs, 2) (portable across x86_64 + arm64)
     */
    {
        void *maybe_open_flags = (void *)pr_get_arg(regs, 2);

        // open_flags is kernel struct; it can safely nofault-read it if if pointer is valid
        // Layout can vary across kernels, so this is best-effort.
        struct {
            int open_flag;
            umode_t mode;
            int acc_mode;
            int intent;
            int lookup_flags;
        } of;

        if (maybe_open_flags &&
            copy_from_kernel_nofault(&of, maybe_open_flags, sizeof(of)) == 0) {
            ctx->flags = (unsigned long)of.open_flag;
            ctx->mode = of.mode;
        }
    }

    return 0;
}

/*
 * Return handler: resolve struct file * return value, compute absolute path, compare to sensitive paths, log.
 */
static int do_filp_open_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct open_call_ctx *ctx = (struct open_call_ctx *)ri->data;
    struct file *filep = NULL;
    char *tmp;
    char path_buf[MAX_PATH_BUF];
    char *resolved;
    bool sensitive, write_attempt;

    // Portable return value fetch across x86_64 + arm64
    filep = (struct file *)pr_get_ret(regs);

    if (!filep || IS_ERR(filep))
        return 0;

    tmp = path_buf;
    resolved = d_path(&filep->f_path, tmp, sizeof(path_buf));
    if (IS_ERR(resolved))
        return 0;

    sensitive = is_sensitive_path(resolved);

    /*
    * Use entry-captured flags if available,
    * otherwise fall back to actual file->f_flags.
    */
    unsigned long eff_flags = ctx->flags ? ctx->flags : filep->f_flags;

    write_attempt = is_writeish(eff_flags);

    if (sensitive) {
        // Log path, flags, mode, pid, ppid, uid, gid, command, time
        printk(KERN_ALERT
               "[PHOTON RING] FILE_OPEN path=\"%s\" flags=0x%lx mode=0%o "
               "pid=%d ppid=%d uid=%u gid=%u comm=\"%s\" ts_ns=%llu %s\n",
               resolved,
               eff_flags,
               ctx->mode,
               ctx->pid,
               ctx->ppid,
               __kuid_val(ctx->kuid),
               __kgid_val(ctx->kgid),
               ctx->comm,
               ctx->ts_ns,
               write_attempt ? "ALERT=WRITE_ATTEMPT" : "ALERT=READ");
    }

    return 0;
}

static struct kretprobe rp_do_filp_open = {
    .kp.symbol_name = "do_filp_open",
    .handler = do_filp_open_ret,
    .entry_handler = do_filp_open_entry,
    .data_size = sizeof(struct open_call_ctx),
    .maxactive = 64, // Can change
};

int file_access_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing file access detector...\n");

    ret = register_kretprobe(&rp_do_filp_open);
    if (ret < 0) {
        printk(KERN_ERR "[PHOTON RING] failed to register kretprobe for do_filp_open: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] file access detector active (kretprobe on do_filp_open)\n");
    return 0;
}

void file_access_detector_exit(void)
{
    unregister_kretprobe(&rp_do_filp_open);
    printk(KERN_INFO "[PHOTON RING] file access detector removed\n");
}