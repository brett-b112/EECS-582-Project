/*
 * ftrace_direct_detector.c — Photon Ring
 *
 * Monitors two ftrace bypass paths not covered by bpf_hook_detector:
 *
 *   ftrace_set_filter    — glob/string filter registration
 *   ftrace_set_notrace   — glob/string notrace registration (same signature)
 *   modify_ftrace_direct — direct-call patching (bypasses ops dispatch)
 *
 * See ftrace_direct_detector.h for full design rationale.
 *
 * All three hooks use kprobes because every target is ftrace infrastructure,
 * which ftrace cannot hook itself.
 *
 * Events are emitted as PHOTON_EVENT_FTRACE_HOOK with a ftrace_hook_data
 * payload.  Severity (always PHOTON_SEV_CRITICAL for this detector) is set
 * in the envelope by photon_log_event — not in the payload struct.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include "photon_ring_arch.h"
#include "watchlists.h"
#include "ftrace_direct_detector.h"
#include "event_manager.h"

/* -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------*/

static bool addr_is_anonymous(unsigned long addr)
{
    char sym[KSYM_SYMBOL_LEN];

    if (!addr)
        return false;
    sprint_symbol_no_offset(sym, addr);
    return (sym[0] == '0' && sym[1] == 'x');
}

/* -------------------------------------------------------------------------
 * Common event emitter
 * -------------------------------------------------------------------------*/

static void emit_event(u8 hook_source,
                       const char *target_sym,
                       unsigned long target_addr,
                       unsigned long new_addr,
                       const char *filter_pattern)
{
    struct ftrace_hook_data payload;

    memset(&payload, 0, sizeof(payload));

    payload.hook_source = hook_source;
    payload.target_addr = target_addr;
    payload.new_addr    = new_addr;

    if (target_sym)
        strncpy(payload.target_symbol, target_sym,
                sizeof(payload.target_symbol) - 1);
    else if (target_addr)
        sprint_symbol_no_offset(payload.target_symbol, target_addr);

    if (new_addr)
        sprint_symbol_no_offset(payload.new_addr_symbol, new_addr);

    if (filter_pattern)
        strncpy(payload.filter_pattern, filter_pattern,
                sizeof(payload.filter_pattern) - 1);

    printk(KERN_ALERT
           "[PHOTON RING] ftrace_direct: src=%u target='%s' (0x%lx) "
           "new='%s' (0x%lx) pattern='%s'\n",
           hook_source,
           payload.target_symbol, target_addr,
           payload.new_addr_symbol, new_addr,
           payload.filter_pattern[0] ? payload.filter_pattern : "");

    /*
     * severity is always CRITICAL for this detector:
     * every intercepted call represents either a glob-matched hook on a
     * watchlisted symbol or a direct call patch — both unambiguously hostile.
     */
    photon_log_event(PHOTON_EVENT_FTRACE_HOOK,
                     PHOTON_DETECTOR_FTRACE,
                     PHOTON_SEV_CRITICAL,
                     &payload, sizeof(payload));
}

/* -------------------------------------------------------------------------
 * Kprobes 1 & 2: ftrace_set_filter / ftrace_set_notrace
 * -------------------------------------------------------------------------*/

static struct kprobe kp_set_filter;
static struct kprobe kp_set_notrace;

static int handle_set_filter_common(struct pt_regs *regs, u8 hook_source)
{
    struct ftrace_ops *ops;
    const char *buf;
    unsigned long ops_func = 0;

    ops = (struct ftrace_ops *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    buf = (const char *)PHOTON_RING_KPROBE_GET_ARG(regs, 1);

    /* NULL buf means clear filters, not an installation */
    if (!buf)
        return 0;

    if (ops && ops->func)
        ops_func = (unsigned long)ops->func;

    if (!addr_is_anonymous(ops_func) && !photon_is_watchlisted(buf))
        return 0;

    emit_event(hook_source, NULL, 0, ops_func, buf);
    return 0;
}

static int handler_set_filter(struct kprobe *p, struct pt_regs *regs)
{
    return handle_set_filter_common(regs, FTRACE_HOOK_SRC_SET_FILTER);
}

static int handler_set_notrace(struct kprobe *p, struct pt_regs *regs)
{
    return handle_set_filter_common(regs, FTRACE_HOOK_SRC_SET_NOTRACE);
}

/* -------------------------------------------------------------------------
 * Kprobe 3: modify_ftrace_direct
 * -------------------------------------------------------------------------*/

static struct kprobe kp_modify_direct;

static int handler_modify_direct(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long ip;
    unsigned long new_addr;
    char ip_sym[KSYM_SYMBOL_LEN];

    ip       = PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    new_addr = PHOTON_RING_KPROBE_GET_ARG(regs, 2);

    sprint_symbol_no_offset(ip_sym, ip);

    if (!addr_is_anonymous(new_addr) && !photon_is_watchlisted(ip_sym))
        return 0;

    emit_event(FTRACE_HOOK_SRC_MODIFY, ip_sym, ip, new_addr, NULL);
    return 0;
}

/* -------------------------------------------------------------------------
 * Init / exit
 * -------------------------------------------------------------------------*/

int ftrace_direct_detector_init(void)
{
    int ret;
    int installed = 0;

    printk(KERN_INFO "[PHOTON RING] initializing ftrace_direct detector...\n");

    /* --- Kprobe 1: ftrace_set_filter --- */
    memset(&kp_set_filter, 0, sizeof(kp_set_filter));
    kp_set_filter.symbol_name = "ftrace_set_filter";
    kp_set_filter.pre_handler = handler_set_filter;

    ret = register_kprobe(&kp_set_filter);
    if (ret)
        printk(KERN_ERR "[PHOTON RING] ftrace_direct: "
               "failed to probe ftrace_set_filter: %d\n", ret);
    else {
        printk(KERN_INFO "[PHOTON RING] ftrace_direct: "
               "probing ftrace_set_filter at %px\n", kp_set_filter.addr);
        installed++;
    }

    /* --- Kprobe 2: ftrace_set_notrace --- */
    memset(&kp_set_notrace, 0, sizeof(kp_set_notrace));
    kp_set_notrace.symbol_name = "ftrace_set_notrace";
    kp_set_notrace.pre_handler = handler_set_notrace;

    ret = register_kprobe(&kp_set_notrace);
    if (ret)
        printk(KERN_ERR "[PHOTON RING] ftrace_direct: "
               "failed to probe ftrace_set_notrace: %d\n", ret);
    else {
        printk(KERN_INFO "[PHOTON RING] ftrace_direct: "
               "probing ftrace_set_notrace at %px\n", kp_set_notrace.addr);
        installed++;
    }

    /* --- Kprobe 3: modify_ftrace_direct --- */
    /*
     * modify_ftrace_direct was added in kernel 5.15.  Its probe failing with
     * -ENOENT on older kernels is expected and non-fatal.
     */
    memset(&kp_modify_direct, 0, sizeof(kp_modify_direct));
    kp_modify_direct.symbol_name = "modify_ftrace_direct";
    kp_modify_direct.pre_handler = handler_modify_direct;

    ret = register_kprobe(&kp_modify_direct);
    if (ret)
        printk(KERN_INFO "[PHOTON RING] ftrace_direct: "
               "modify_ftrace_direct not available (kernel < 5.15?): %d\n", ret);
    else {
        printk(KERN_INFO "[PHOTON RING] ftrace_direct: "
               "probing modify_ftrace_direct at %px\n", kp_modify_direct.addr);
        installed++;
    }

    if (installed == 0) {
        printk(KERN_ERR "[PHOTON RING] ftrace_direct: "
               "no probes installed — aborting\n");
        return -ENODEV;
    }

    printk(KERN_INFO "[PHOTON RING] ftrace_direct detector active "
           "(%d probe(s) installed)\n", installed);
    return 0;
}

void ftrace_direct_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing ftrace_direct detector...\n");

    if (kp_modify_direct.addr)
        unregister_kprobe(&kp_modify_direct);
    if (kp_set_notrace.addr)
        unregister_kprobe(&kp_set_notrace);
    if (kp_set_filter.addr)
        unregister_kprobe(&kp_set_filter);

    printk(KERN_INFO "[PHOTON RING] ftrace_direct detector removed\n");
}