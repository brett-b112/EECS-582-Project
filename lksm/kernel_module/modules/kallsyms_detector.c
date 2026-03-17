/*
 * kallsyms_detector.c — Photon Ring
 *
 * Hooks kallsyms_lookup_name via ftrace (observer-only, no IPMODIFY) and
 * inspects every symbol name passed to it from outside this module.
 *
 * Address resolution
 * ------------------
 * kallsyms_lookup_name is not exported on kernels >= 5.7 so it cannot be
 * referenced as a linker symbol from an out-of-tree module.  We obtain its
 * runtime address from kprobe_detector_get_kallsyms_addr(), which resolves
 * it during kprobe_detector_init() via the kprobe bootstrap technique.
 * This means kprobe_detector MUST appear before kallsyms_detector in the
 * detectors[] array in main.c.
 *
 * Watchlists
 * ----------
 *  CRITICAL    — unambiguously hostile; no legitimate module needs these
 *                at runtime (tainted_mask, sys_call_table, …).
 *  HOOK_TARGET — functions that are common IPMODIFY hook destinations in
 *                known rootkits (filldir64, tcp4_seq_show, commit_creds, …).
 *  AUDIT       — noteworthy for correlation but not individually conclusive
 *                (module_alloc, ftrace_ops_list, …).
 *
 * Wire format
 * -----------
 * Events are emitted as PHOTON_EVENT_KPROBE_REG with a kprobe_event_data
 * payload — the same type the kprobe detector uses — so userspace needs no
 * parser changes:
 *   symbol_name  "<symname>  (comm/pid)"
 *   addr         caller instruction pointer (parent_ip from ftrace)
 *   flags        threat tier: KALLSYMS_FLAG_CRITICAL / _HOOK_TARGET / _AUDIT
 */

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/module.h>
#include "../include/photon_ring_arch.h"
#include "../include/kallsyms_detector.h"
#include "../include/kprobe_detector.h"
#include "../include/event_manager.h"

/* -------------------------------------------------------------------------
 * Watchlists
 * -------------------------------------------------------------------------*/

/*
 * CRITICAL — looking up any of these from outside a known-good module is
 * unambiguously hostile.
 */
static const char * const critical_syms[] = {
    "tainted_mask",         /* Singularity reset_tainted — erase forensic trail */
    "sys_call_table",       /* syscall table hijack                              */
    "ia32_sys_call_table",  /* 32-bit compat syscall table hijack                */
    "_stext",               /* raw kernel text base — KASLR defeat               */
    "entry_SYSCALL_64",     /* syscall entry point patching                      */
    NULL
};

/*
 * HOOK_TARGET — functions rootkits commonly redirect via IPMODIFY hooks.
 * A lookup here almost certainly precedes hook installation.
 */
static const char * const hook_target_syms[] = {
    /* filesystem / directory hiding */
    "filldir64",
    "filldir",
    "iterate_dir",
    /* network hiding */
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    /* privilege escalation */
    "commit_creds",
    "prepare_kernel_cred",
    "cap_capable",
    /* process / module hiding */
    "proc_pid_readdir",
    "proc_pid_lookup",
    /* signal interception (C2 channel) */
    "sys_kill",
    "do_send_sig_info",
    NULL
};

/*
 * AUDIT — worth recording for correlation but not conclusive alone.
 */
static const char * const audit_syms[] = {
    "module_alloc",           /* custom code injection           */
    "set_memory_x",           /* marking memory executable       */
    "ftrace_ops_list",        /* enumerating active ftrace hooks */
    "kthread_create_on_node", /* covert thread creation          */
    "find_module",            /* module list walking             */
    NULL
};

/* -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------*/

static bool match_list(const char * const *list, const char *name)
{
    for (; *list; list++) {
        if (strcmp(*list, name) == 0)
            return true;
    }
    return false;
}

/*
 * emit_event - build and dispatch a kprobe_event_data payload.
 *
 * Reuses kprobe_event_data and PHOTON_EVENT_KPROBE_REG so userspace needs
 * no wire-format changes:
 *   symbol_name  "<symname>  (comm/pid)"  — human-readable annotation
 *   addr         caller IP (parent_ip)    — locates the offending code
 *   flags        threat tier              — for programmatic triage
 */
static notrace void emit_event(const char *symname,
                               unsigned long caller_ip,
                               u32 tier_flag)
{
    struct kprobe_event_data event_data;

    memset(&event_data, 0, sizeof(event_data));

    snprintf(event_data.symbol_name, sizeof(event_data.symbol_name),
             "%s  (%s/%d)", symname, current->comm, current->pid);

    event_data.addr  = caller_ip;
    event_data.flags = tier_flag;

    photon_log_event(PHOTON_EVENT_KPROBE_REG,
                     PHOTON_DETECTOR_KPROBE,
                     &event_data,
                     sizeof(event_data));
}

/* -------------------------------------------------------------------------
 * Ftrace hook
 * -------------------------------------------------------------------------*/

static struct ftrace_ops kallsyms_ops;

/*
 * hook_kallsyms_lookup - ftrace callback on every kallsyms_lookup_name call.
 *
 * 1. Reject calls originating from within this module (our own lookups).
 * 2. Extract symname from arg0 and validate the pointer.
 * 3. Classify against the three watchlists in severity order.
 * 4. Emit an event on any match; silently drop unclassified lookups.
 */
static notrace void hook_kallsyms_lookup(unsigned long ip,
                                         unsigned long parent_ip,
                                         struct ftrace_ops *ops,
                                         struct ftrace_regs *fregs)
{
    const char *symname;

    /*
     * Ignore our own symbol lookups.  within_module() is safe here: we hold
     * no locks and are in a preempt-disabled ftrace context.
     */
    if (within_module(parent_ip, THIS_MODULE))
        return;

    symname = (const char *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!symname)
        return;

    /* classify in severity order — emit the first match and return */
    if (match_list(critical_syms, symname)) {
        printk(KERN_ALERT
               "[PHOTON RING] CRITICAL kallsyms_lookup_name(\"%s\") "
               "from outside known module — "
               "caller_ip=0x%lx comm=%s pid=%d\n",
               symname, parent_ip, current->comm, current->pid);
        emit_event(symname, parent_ip, KALLSYMS_FLAG_CRITICAL);
        return;
    }

    if (match_list(hook_target_syms, symname)) {
        printk(KERN_ALERT
               "[PHOTON RING] SUSPICIOUS kallsyms_lookup_name(\"%s\") "
               "— likely hook installation, "
               "caller_ip=0x%lx comm=%s pid=%d\n",
               symname, parent_ip, current->comm, current->pid);
        emit_event(symname, parent_ip, KALLSYMS_FLAG_HOOK_TARGET);
        return;
    }

    if (match_list(audit_syms, symname)) {
        printk(KERN_INFO
               "[PHOTON RING] AUDIT kallsyms_lookup_name(\"%s\") "
               "caller_ip=0x%lx comm=%s pid=%d\n",
               symname, parent_ip, current->comm, current->pid);
        emit_event(symname, parent_ip, KALLSYMS_FLAG_AUDIT);
        return;
    }

    /* unclassified — drop silently to avoid event noise */
}

/* -------------------------------------------------------------------------
 * Init / exit
 * -------------------------------------------------------------------------*/

int kallsyms_detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing kallsyms detector...\n");

    /*
     * Obtain the address resolved by kprobe_detector_init().
     * If this returns 0, kprobe_detector either has not run yet or its
     * bootstrap failed — both are fatal for this detector.
     */
    addr = kprobe_detector_get_kallsyms_addr();
    if (!addr) {
        printk(KERN_ERR
               "[PHOTON RING] kallsyms detector: kallsyms_lookup_name address "
               "not available — ensure kprobe_detector initializes first\n");
        return -ENOENT;
    }

    printk(KERN_INFO
           "[PHOTON RING] kallsyms detector: using kallsyms_lookup_name "
           "at 0x%lx\n", addr);

    kallsyms_ops.func  = hook_kallsyms_lookup;
    kallsyms_ops.flags = PHOTON_RING_FTRACE_FLAGS; /* SAVE_REGS | RECURSION */

    ret = ftrace_set_filter_ip(&kallsyms_ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR
               "[PHOTON RING] kallsyms detector: ftrace_set_filter_ip "
               "failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&kallsyms_ops);
    if (ret) {
        printk(KERN_ERR
               "[PHOTON RING] kallsyms detector: register_ftrace_function "
               "failed: %d\n", ret);
        ftrace_set_filter_ip(&kallsyms_ops, addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO
           "[PHOTON RING] kallsyms detector active — "
           "monitoring %zu critical / %zu hook-target / %zu audit symbols\n",
           ARRAY_SIZE(critical_syms)    - 1,   /* -1 for NULL sentinel */
           ARRAY_SIZE(hook_target_syms) - 1,
           ARRAY_SIZE(audit_syms)       - 1);

    return 0;
}

void kallsyms_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing kallsyms detector...\n");

    unregister_ftrace_function(&kallsyms_ops);

    /*
     * Pass addr=0, remove=1 to clear all filters on this ops struct —
     * identical to how kprobe_detector_exit works.
     */
    ftrace_set_filter_ip(&kallsyms_ops, 0, 1, 0);

    printk(KERN_INFO "[PHOTON RING] kallsyms detector removed\n");
}