/*
 * kretprobe_detector.c — Photon Ring
 *
 * Closes two registration gaps left open by kprobe_detector:
 *
 *   1. register_kretprobe — monitored via ftrace hook.
 *      kprobe_detector hooks register_kprobe, which register_kretprobe calls
 *      internally, but by the time that inner call fires kp->symbol_name has
 *      already been NULLed and only kp->addr remains.  Hooking
 *      register_kretprobe directly lets us read the original symbol name,
 *      both handler addresses (entry and return), and maxactive before any
 *      of that context is lost.
 *
 *   2. register_kprobes (plural) — monitored via ftrace hook.
 *      kprobe_detector catches every element of a batch via its inner-loop
 *      calls to register_kprobe, but loses the batch size.  Hooking
 *      register_kprobes gives us num so userspace can correlate a burst that
 *      arrived in a single atomic call.
 *
 * Events are emitted as PHOTON_EVENT_PROBE_KRETPROBE with a probe_hook_data
 * payload.  Severity is set by this detector and travels in the envelope.
 */

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include "photon_ring_arch.h"
#include "watchlists.h"
#include "kretprobe_detector.h"
#include "event_manager.h"

/* -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------*/

static bool handler_is_anonymous(unsigned long addr)
{
    char sym[KSYM_SYMBOL_LEN];

    if (!addr)
        return false;
    sprint_symbol_no_offset(sym, addr);
    return (sym[0] == '0' && sym[1] == 'x');
}

/*
 * build_and_emit - fill a probe_hook_data, derive severity, and log the event.
 */
static void build_and_emit(const char *symbol_name,
                            unsigned long target_addr,
                            unsigned long handler_addr,
                            unsigned long entry_addr,
                            int maxactive,
                            int batch_count,
                            u32 flags)
{
    struct probe_hook_data payload;
    u8 severity;

    memset(&payload, 0, sizeof(payload));

    if (symbol_name)
        strncpy(payload.symbol_name, symbol_name,
                sizeof(payload.symbol_name) - 1);

    payload.target_addr  = target_addr;
    payload.handler_addr = handler_addr;
    payload.entry_addr   = entry_addr;
    payload.maxactive    = maxactive;
    payload.batch_count  = batch_count;
    payload.flags        = flags;

    /* Severity: CRITICAL if anon handler or watchlisted; SUSPICIOUS otherwise */
    if (flags & (PROBE_FLAG_ANON_HANDLER | PROBE_FLAG_WATCHLISTED))
        severity = PHOTON_SEV_CRITICAL;
    else
        severity = PHOTON_SEV_SUSPICIOUS;

    printk("%s[PHOTON RING] kretprobe registration: symbol='%s' "
           "target=0x%lx handler=0x%lx entry=0x%lx "
           "maxactive=%d batch=%d flags=0x%x\n",
           (severity == PHOTON_SEV_CRITICAL) ? KERN_ALERT : KERN_WARNING,
           payload.symbol_name[0] ? payload.symbol_name : "<unknown>",
           target_addr, handler_addr, entry_addr,
           maxactive, batch_count, flags);

    photon_log_event(PHOTON_EVENT_PROBE_KRETPROBE,
                     PHOTON_DETECTOR_KRETPROBE,
                     severity,
                     &payload, sizeof(payload));
}

/* -------------------------------------------------------------------------
 * Hook 1: register_kretprobe
 * -------------------------------------------------------------------------*/

static struct ftrace_ops ops_kretprobe;

static notrace void hook_register_kretprobe(unsigned long ip,
                                             unsigned long parent_ip,
                                             struct ftrace_ops *ops,
                                             struct ftrace_regs *fregs)
{
    struct kretprobe *rp;
    const char *symname;
    unsigned long handler_addr;
    unsigned long entry_addr;
    u32 flags = 0;

    rp = (struct kretprobe *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!rp)
        return;

    if (within_module(parent_ip, THIS_MODULE))
        return;

    symname      = rp->kp.symbol_name;
    handler_addr = (unsigned long)rp->handler;
    entry_addr   = (unsigned long)rp->entry_handler;

    if (photon_is_watchlisted(symname))
        flags |= PROBE_FLAG_WATCHLISTED;

    if (handler_is_anonymous(handler_addr))
        flags |= PROBE_FLAG_ANON_HANDLER;

    if (entry_addr && handler_is_anonymous(entry_addr))
        flags |= PROBE_FLAG_ANON_HANDLER;

    if (rp->maxactive > KRETPROBE_MAXACTIVE_THRESHOLD)
        flags |= PROBE_FLAG_HIGH_ACTIVE;

    if (!flags)
        return;

    build_and_emit(symname,
                   (unsigned long)rp->kp.addr,
                   handler_addr,
                   entry_addr,
                   rp->maxactive,
                   1,
                   flags);
}

/* -------------------------------------------------------------------------
 * Hook 2: register_kprobes (batch)
 * -------------------------------------------------------------------------*/

static struct ftrace_ops ops_kprobes_batch;

static notrace void hook_register_kprobes(unsigned long ip,
                                           unsigned long parent_ip,
                                           struct ftrace_ops *ops,
                                           struct ftrace_regs *fregs)
{
    struct kprobe **kps;
    unsigned long num_ul;
    int num, i;

    kps    = (struct kprobe **)PHOTON_RING_GET_ARG(fregs, 0);
    num_ul = PHOTON_RING_GET_ARG(fregs, 1);

    if (!kps || num_ul == 0)
        return;

    if (within_module(parent_ip, THIS_MODULE))
        return;

    num = (int)min_t(unsigned long, num_ul, 64UL);

    for (i = 0; i < num; i++) {
        struct kprobe *kp;
        const char *symname;
        unsigned long handler_addr;
        u32 flags = PROBE_FLAG_BATCH;

        if (!kps[i])
            continue;

        kp           = kps[i];
        symname      = kp->symbol_name;
        handler_addr = (unsigned long)kp->pre_handler;

        if (photon_is_watchlisted(symname))
            flags |= PROBE_FLAG_WATCHLISTED;

        if (handler_is_anonymous(handler_addr))
            flags |= PROBE_FLAG_ANON_HANDLER;

        /* skip events that carry no threat signal beyond the batch flag */
        if (!(flags & ~PROBE_FLAG_BATCH))
            continue;

        build_and_emit(symname,
                       (unsigned long)kp->addr,
                       handler_addr,
                       0,
                       0,
                       (int)num_ul,
                       flags);
    }
}

/* -------------------------------------------------------------------------
 * Init / exit
 * -------------------------------------------------------------------------*/

int kretprobe_detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing kretprobe detector...\n");

    /* --- Hook 1: register_kretprobe --- */
    addr = (unsigned long)register_kretprobe;
    printk(KERN_INFO "[PHOTON RING] register_kretprobe at 0x%lx\n", addr);

    ops_kretprobe.func  = hook_register_kretprobe;
    ops_kretprobe.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops_kretprobe, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] kretprobe detector: "
               "ftrace_set_filter_ip(register_kretprobe) failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&ops_kretprobe);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] kretprobe detector: "
               "register_ftrace_function(register_kretprobe) failed: %d\n", ret);
        ftrace_set_filter_ip(&ops_kretprobe, addr, 1, 0);
        return ret;
    }

    /* --- Hook 2: register_kprobes (plural / batch) --- */
    addr = (unsigned long)register_kprobes;
    printk(KERN_INFO "[PHOTON RING] register_kprobes at 0x%lx\n", addr);

    ops_kprobes_batch.func  = hook_register_kprobes;
    ops_kprobes_batch.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops_kprobes_batch, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] kretprobe detector: "
               "ftrace_set_filter_ip(register_kprobes) failed: %d\n", ret);
        goto unwind_kretprobe;
    }

    ret = register_ftrace_function(&ops_kprobes_batch);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] kretprobe detector: "
               "register_ftrace_function(register_kprobes) failed: %d\n", ret);
        ftrace_set_filter_ip(&ops_kprobes_batch, addr, 1, 0);
        goto unwind_kretprobe;
    }

    printk(KERN_INFO "[PHOTON RING] kretprobe detector active — "
           "monitoring register_kretprobe and register_kprobes\n");
    return 0;

unwind_kretprobe:
    unregister_ftrace_function(&ops_kretprobe);
    ftrace_set_filter_ip(&ops_kretprobe,
                         (unsigned long)register_kretprobe, 1, 0);
    return ret;
}

void kretprobe_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing kretprobe detector...\n");
    unregister_ftrace_function(&ops_kprobes_batch);
    ftrace_set_filter_ip(&ops_kprobes_batch, 0, 1, 0);
    unregister_ftrace_function(&ops_kretprobe);
    ftrace_set_filter_ip(&ops_kretprobe, 0, 1, 0);
    printk(KERN_INFO "[PHOTON RING] kretprobe detector removed\n");
}