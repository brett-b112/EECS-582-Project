/*
 * kallsyms_detector.c — Photon Ring
 *
 * Hooks kallsyms_lookup_name via ftrace (observer-only, no IPMODIFY) and
 * inspects every symbol name passed to it from outside this module.
 *
 * Address resolution
 * ------------------
 * kallsyms_lookup_name is not exported on kernels >= 5.7, so we obtain its
 * runtime address from kprobe_detector_get_kallsyms_addr(), which resolves
 * it during kprobe_detector_init() via the kprobe bootstrap technique.
 * kprobe_detector MUST appear before kallsyms_detector in detectors[].
 *
 * Events
 * ------
 * PHOTON_EVENT_PROBE_KALLSYMS with a probe_hook_data payload:
 *   symbol_name  — the looked-up symbol name, with "comm/pid" appended
 *   target_addr  — parent_ip (the instruction that called kallsyms_lookup_name)
 *   flags        — PROBE_FLAG_WATCHLISTED always set (we only emit on matches)
 * severity       — PHOTON_SEV_CRITICAL (envelope field, set here)
 */

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/module.h>
#include "photon_ring_arch.h"
#include "watchlists.h"
#include "kallsyms_detector.h"
#include "kprobe_detector.h"
#include "event_manager.h"

static struct ftrace_ops kallsyms_ops;

static notrace void hook_kallsyms_lookup(unsigned long ip,
                                         unsigned long parent_ip,
                                         struct ftrace_ops *ops,
                                         struct ftrace_regs *fregs)
{
    const char *symname;
    struct probe_hook_data payload;

    if (within_module(parent_ip, THIS_MODULE))
        return;

    symname = (const char *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!symname || !photon_is_watchlisted(symname))
        return;

    printk(KERN_ALERT
           "[PHOTON RING] SUSPICIOUS kallsyms_lookup_name(\"%s\") "
           "from outside known module — caller_ip=0x%lx comm=%s pid=%d\n",
           symname, parent_ip, current->comm, current->pid);

    memset(&payload, 0, sizeof(payload));
    /*
     * Embed comm/pid in symbol_name for legacy readability in syslog.
     * The envelope's caller_comm/caller_pid fields are the canonical source
     * for Elasticsearch; this annotation is for human log readers only.
     */
    snprintf(payload.symbol_name, sizeof(payload.symbol_name),
             "%s  (%s/%d)", symname, current->comm, current->pid);
    payload.target_addr = parent_ip;   /* IP that initiated the lookup      */
    payload.batch_count = 1;
    payload.flags       = PROBE_FLAG_WATCHLISTED;

    photon_log_event(PHOTON_EVENT_PROBE_KALLSYMS,
                     PHOTON_DETECTOR_KPROBE,
                     PHOTON_SEV_CRITICAL,
                     &payload, sizeof(payload));
}

int kallsyms_detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing kallsyms detector...\n");

    addr = kprobe_detector_get_kallsyms_addr();
    if (!addr) {
        printk(KERN_ERR
               "[PHOTON RING] kallsyms detector: kallsyms_lookup_name address "
               "not available — ensure kprobe_detector initializes first\n");
        return -ENOENT;
    }

    printk(KERN_INFO "[PHOTON RING] kallsyms detector: "
           "kallsyms_lookup_name at 0x%lx\n", addr);

    kallsyms_ops.func  = hook_kallsyms_lookup;
    kallsyms_ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&kallsyms_ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] kallsyms detector: "
               "ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&kallsyms_ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] kallsyms detector: "
               "register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&kallsyms_ops, addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] kallsyms detector active\n");
    return 0;
}

void kallsyms_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing kallsyms detector...\n");
    unregister_ftrace_function(&kallsyms_ops);
    ftrace_set_filter_ip(&kallsyms_ops, 0, 1, 0);
    printk(KERN_INFO "[PHOTON RING] kallsyms detector removed\n");
}