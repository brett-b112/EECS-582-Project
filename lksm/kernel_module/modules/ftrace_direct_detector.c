/*
 * ftrace_direct_detector.c — Photon Ring
 *
 * Monitors ftrace bypass paths not covered by bpf_hook_detector:
 *
 *   ftrace_set_filter    — glob/string filter registration
 *   ftrace_set_notrace   — glob/string notrace registration (same signature)
 *   ftrace_set_filter_ip — address-based filter registration (most rootkits
 *                          use this exclusively; no string pattern involved)
 *   modify_ftrace_direct — direct-call patching (bypasses ops dispatch)
 *
 * See ftrace_direct_detector.h for full design rationale.
 *
 * All four hooks use kprobes because every target is ftrace infrastructure,
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
#include "watchlist_resolver.h"
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
 * Kprobe 4: ftrace_set_filter_ip
 *
 * This is the primary hook installation path used by ftrace-based rootkits.
 * Unlike ftrace_set_filter (which takes a glob string), ftrace_set_filter_ip
 * takes a pre-resolved kernel address directly:
 *
 *   int ftrace_set_filter_ip(struct ftrace_ops *ops,
 *                            unsigned long ip,
 *                            int remove,
 *                            int reset);
 *
 * We emit an event when:
 *   - remove == 0  (installation, not removal)
 *   AND either:
 *   - ip resolves to a watchlisted symbol via the watchlist_resolver dict, OR
 *   - ops->func is anonymous (points into an unknown/unlisted module)
 *
 * The watchlist_resolver dictionary is used here rather than
 * photon_is_watchlisted(name) because the rootkit never passes a symbol
 * name string — it only passes the raw address.  The resolver maps that
 * address back to the name we stored during kprobe_detector_init.
 * -------------------------------------------------------------------------*/

static struct kprobe kp_set_filter_ip;

static int handler_set_filter_ip(struct kprobe *p, struct pt_regs *regs)
{
    struct ftrace_ops *ops;
    unsigned long      ip;
    int                remove;
    unsigned long      ops_func = 0;
    const char        *resolved_name;
    char               ip_sym[KSYM_SYMBOL_LEN];

    ops    = (struct ftrace_ops *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    ip     = (unsigned long)PHOTON_RING_KPROBE_GET_ARG(regs, 1);
    remove = (int)PHOTON_RING_KPROBE_GET_ARG(regs, 2);

    /* Only care about installations, not removals. */
    if (remove)
        return 0;

    if (!ip)
        return 0;

    if (ops && ops->func)
        ops_func = (unsigned long)ops->func;

    /*
     * Try to resolve ip to a watchlisted name via the pre-built dictionary.
     * This catches rootkits that resolve addresses themselves and never pass
     * a symbol name string to any kernel API.
     */
    resolved_name = watchlist_resolver_lookup_name(ip);

    if (!resolved_name && !addr_is_anonymous(ops_func)) {
        /*
         * ip is not watchlisted and ops->func is a known symbol — not
         * suspicious enough to emit.  Legitimate modules (including Photon
         * Ring itself) install ftrace hooks this way constantly.
         *
         * The within_module check is intentionally absent here: we rely on
         * the watchlist and anonymity checks instead, because kprobes do not
         * have a parent_ip available in pre_handler context.
         */
        return 0;
    }

    /*
     * Fall back to sprint_symbol for the target_sym field if the resolver
     * didn't match — addr_is_anonymous(ops_func) branch lands here.
     */
    if (resolved_name) {
        emit_event(FTRACE_HOOK_SRC_SET_FILTER,
                   resolved_name, ip, ops_func, NULL);
    } else {
        sprint_symbol_no_offset(ip_sym, ip);
        emit_event(FTRACE_HOOK_SRC_SET_FILTER,
                   ip_sym, ip, ops_func, NULL);
    }

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

    /* --- Kprobe 4: ftrace_set_filter_ip --- */
    /*
     * This is the path most ftrace-based rootkits actually use — they resolve
     * addresses via kallsyms_lookup_name and pass them directly to
     * ftrace_set_filter_ip, never touching ftrace_set_filter (the string
     * variant).  Without this probe, those hook installations are invisible.
     */
    memset(&kp_set_filter_ip, 0, sizeof(kp_set_filter_ip));
    kp_set_filter_ip.symbol_name = "ftrace_set_filter_ip";
    kp_set_filter_ip.pre_handler = handler_set_filter_ip;

    ret = register_kprobe(&kp_set_filter_ip);
    if (ret)
        printk(KERN_ERR "[PHOTON RING] ftrace_direct: "
               "failed to probe ftrace_set_filter_ip: %d\n", ret);
    else {
        printk(KERN_INFO "[PHOTON RING] ftrace_direct: "
               "probing ftrace_set_filter_ip at %px\n", kp_set_filter_ip.addr);
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

    if (kp_set_filter_ip.addr)
        unregister_kprobe(&kp_set_filter_ip);
    if (kp_modify_direct.addr)
        unregister_kprobe(&kp_modify_direct);
    if (kp_set_notrace.addr)
        unregister_kprobe(&kp_set_notrace);
    if (kp_set_filter.addr)
        unregister_kprobe(&kp_set_filter);

    printk(KERN_INFO "[PHOTON RING] ftrace_direct detector removed\n");
}