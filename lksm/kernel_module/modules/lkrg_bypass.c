// hook_lkrg_bypass.c
// Detects LKRG bypass attempts via integrity tampering, cred abuse, and watchdog/timer manipulation
//
// Detection targets:
//   1. Kernel text patching (LKRG integrity bypass)
//   2. Credential escalation bypassing validation
//   3. Watchdog/timer disabling
//   4. Function pointer hijacking
//
// Strategy:
// Hook sensitive kernel functions (commit_creds, timers, memory write paths)
// and cross-correlate suspicious behavior. LKRG protects kernel integrity,
// so any attempt to modify kernel text or bypass credential validation
// produces detectable side effects at these lower levels.

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/ratelimit.h>
#include <linux/kallsyms.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include "../include/photon_ring_arch.h"
#include "../include/lkrg_bypass.h"
/* ============================= */
/* Severity & MITRE Mapping      */
/* ============================= */

typedef enum
{
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

static inline const char *severity_to_str(severity_t sev)
{
    switch (sev)
    {
    case SEV_CRITICAL:
        return "CRITICAL";
    case SEV_HIGH:
        return "HIGH";
    case SEV_MEDIUM: 
        return "MEDIUM";
    case SEV_LOW:
        return "LOW";
    default:
        return "INFO";
    }
}
/* MITRE ATT&CK Mappings */
#define MITRE_PRIV_ESC "T1548"  /* Abuse Elevation Control */
#define MITRE_DEF_EVADE "T1562" /* Impair Defenses */

/* Escalation tracking */
static atomic_t suspicious_events = ATOMIC_INIT(0);
// int freq = atomic_inc_return(&suspicious_events);
static int hooks_installed = 0;
static severity_t calc_severity(bool cred_escalation,
                                bool timer_abuse,
                                int freq)
{
    if (cred_escalation && freq > 3)
        return SEV_CRITICAL;
    if (cred_escalation)
        return SEV_HIGH;
    if (timer_abuse)
        return SEV_MEDIUM;
    return SEV_LOW;
}

// esclation scoring
static int calc_confidence(bool cred_escalation,
                           bool timer_abuse)
{
    int score = 0;

    if (cred_escalation)
        score += 70;
    if (timer_abuse)
        score += 40;

    if (score > 100)
        score = 100;
    return score;
}
/* ============================= */
/* Rate Limiting                 */
/* ============================= */

// static DEFINE_RATELIMIT_STATE(mem_rl, HZ, 5);
static DEFINE_RATELIMIT_STATE(cred_rl, HZ, 10);
static DEFINE_RATELIMIT_STATE(timer_rl, HZ, 5);

/* ============================= */
/* Helpers                       */
/* ============================= */

/*
 * Check if an address lies in kernel text region.
 * Used to detect code patching (LKRG bypass).
 */

// static bool is_kernel_text_addr(unsigned long addr)
// {
//     return false;
// }
/*
 * Simple heuristic: detect suspicious UID escalation
 */
static bool is_suspicious_cred(const struct cred *old,
                               const struct cred *new)
{
    return (old->uid.val != 0 && new->uid.val == 0);
}

/* ============================= */
/* Detection Logic               */
/* ============================= */

/*
 * Detect credential tampering (LKRG bypass attempt)
 */
static notrace void detect_cred_change(struct cred *new)
{
    if (!new)
        return;

    int freq = atomic_inc_return(&suspicious_events);
    severity_t sev = calc_severity(true, false, freq);
    int confidence = calc_confidence(true, false);

    /* Downgrade expected privilege escalation */
    if (!strcmp(current->comm, "sudo") ||
        !strcmp(current->comm, "su")) {
        sev = SEV_INFO;
        confidence = 10;
    }

    printk(KERN_ALERT
           "[PHOTON][%s][conf=%d%%][MITRE=%s] commit_creds PID=%d (%s) new_uid=%d\n",
           severity_to_str(sev),
           confidence,
           MITRE_PRIV_ESC,
           current->pid,
           current->comm,
           new->uid.val);
}

/*
 * Detect kernel memory modification attempts
 */
// static notrace void detect_kernel_write(unsigned long addr)
// {
//     if (is_kernel_text_addr(addr) && __ratelimit(&mem_rl))
//     {
//         printk(KERN_ALERT
//                "[PHOTON RING] LKRG_BYPASS_ALERT: Kernel text write attempt "
//                "at %px by PID %d (%s)\n",
//                (void *)addr, current->pid, current->comm);
//     }
// }

/*
 * Detect watchdog/timer tampering
 */
static notrace void detect_timer_mod(void *timer_addr)
{
    severity_t sev;
    int confidence;

    if (__ratelimit(&timer_rl))
    {

        // suspicious_events++;

        // sev = calc_severity(false, true, suspicious_events);
        int freq = atomic_inc_return(&suspicious_events);

        sev = calc_severity(false, true, freq);
        confidence = calc_confidence(false, true);

        printk(KERN_WARNING
               "[PHOTON][%s][conf=%d%%][MITRE=%s] Timer modification PID=%d (%s) target=%px\n",
               severity_to_str(sev),
               confidence,
               MITRE_DEF_EVADE,
               current->pid,
               current->comm,
               timer_addr);
    }
}

/* ============================= */
/* Ftrace Hooks                  */
/* ============================= */

/*
 * commit_creds hook
 */
static notrace void hook_commit_creds(unsigned long ip,
                                      unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct ftrace_regs *fregs)
{
    struct pt_regs *regs;
    struct cred *new;

    regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!regs)
        return;

    new = (struct cred *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    detect_cred_change(new);
}

/*
 * set_memory_rw / text_poke equivalent detection
 */
// static notrace void hook_mem_write(unsigned long ip,
//                                    unsigned long parent_ip,
//                                    struct ftrace_ops *ops,
//                                    struct ftrace_regs *fregs)
// {
//     struct pt_regs *regs;
//     unsigned long addr;

//     regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
//     if (!regs)
//         return;

//     addr = (unsigned long)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
//     // detect_kernel_write(addr);
// }

/*
 * timer deletion/modification hook
 */
static notrace void hook_timer(unsigned long ip,
                               unsigned long parent_ip,
                               struct ftrace_ops *ops,
                               struct ftrace_regs *fregs)
{
    struct pt_regs *regs;
    void *timer;

    regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!regs)
        return;

    timer = (void *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    detect_timer_mod(timer);
}

/* ============================= */
/* Ftrace Ops                    */
/* ============================= */

static struct ftrace_ops cred_ops = {
    .func = hook_commit_creds,
    .flags = PHOTON_RING_FTRACE_FLAGS,
};

// static struct ftrace_ops mem_ops = {
//     .func = hook_mem_write,
//     .flags = PHOTON_RING_FTRACE_FLAGS,
// };

static struct ftrace_ops timer_ops = {
    .func = hook_timer,
    .flags = PHOTON_RING_FTRACE_FLAGS,
};

/* ============================= */
/* Symbol Targets                */
/* ============================= */

static const char *cred_names[] = {
    "commit_creds",
    NULL,
};

// static const char *mem_names[] = {
//     "text_poke",
//     "set_memory_rw",
//     NULL,
// };

static const char *timer_names[] = {
    "del_timer",
    "mod_timer",
    NULL,
};

/* ============================= */
/* Filter Setup Helper           */
/* ============================= */

static int setup_ftrace_filter(struct ftrace_ops *ops,
                               const char **names)
{
    int i, ret;
    bool ok = false;

    for (i = 0; names[i]; i++)
    {
        ret = ftrace_set_filter(ops,
                                (unsigned char *)names[i],
                                strlen(names[i]),
                                !ok);
        if (!ret)
        {
            ok = true;
            printk(KERN_INFO
                   "[PHOTON RING] Filter set for %s\n",
                   names[i]);
        }
    }

    return ok ? 0 : -ENOENT;
}

/* ============================= */
/* Init / Exit                   */
/* ============================= */

int lkrg_bypass_init(void)
{
    int ret;

    printk(KERN_INFO
           "[PHOTON RING] Initializing LKRG bypass detector...\n");

    hooks_installed = 0;

    /* Credential hooks */
    if (setup_ftrace_filter(&cred_ops, cred_names) == 0)
    {
        ret = register_ftrace_function(&cred_ops);
        if (ret)
            return ret;
        hooks_installed++;
    }

    /* Memory hooks */
    // if (setup_ftrace_filter(&mem_ops, mem_names) == 0)
    // {
    //     ret = register_ftrace_function(&mem_ops);
    //     if (ret)
    //         goto err;
    //     hooks_installed++;
    // }

    /* Timer hooks */
    if (setup_ftrace_filter(&timer_ops, timer_names) == 0)
    {
        ret = register_ftrace_function(&timer_ops);
        if (ret)
            goto err;
        hooks_installed++;
    }

    if (!hooks_installed)
    {
        printk(KERN_ERR
               "[PHOTON RING] No LKRG hooks installed\n");
        return -ENOENT;
    }

    printk(KERN_INFO
           "[PHOTON RING] LKRG bypass detector active (%d hooks)\n",
           hooks_installed);

    return 0;

err:
    // if (hooks_installed >= 2)
    //     unregister_ftrace_function(&mem_ops);
    if (hooks_installed >= 1)
        unregister_ftrace_function(&cred_ops);
    hooks_installed = 0;
    return ret;
}

void lkrg_bypass_exit(void)
{
    printk(KERN_INFO
           "[PHOTON RING] Removing LKRG bypass detector...\n");

    if (hooks_installed >= 3)
        unregister_ftrace_function(&timer_ops);
    // if (hooks_installed >= 2)
    //     unregister_ftrace_function(&mem_ops);
    if (hooks_installed >= 1)
        unregister_ftrace_function(&cred_ops);

    hooks_installed = 0;

    printk(KERN_INFO
           "[PHOTON RING] LKRG bypass detector removed\n");
}