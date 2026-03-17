/*
 * bpf_hook_detector.c - Detects ftrace hooks targeting BPF-critical kernel functions
 *
 * Unlike other Photon Ring detectors (kprobe_detector, become_root_detector, etc.)
 * which use ftrace to hook their targets, this detector uses kprobes instead.
 *
 * Why kprobes instead of ftrace?
 * Our target function is ftrace_set_filter_ip — part of ftrace's own infrastructure.
 * Ftrace refuses to hook itself (returns -EINVAL / -22) because doing so would
 * create recursion: ftrace_set_filter_ip would need to call itself to set up
 * the filter, which is a circular dependency. Kprobes is a separate instrumentation
 * mechanism that inserts breakpoint instructions (BRK on ARM64, INT3 on x86)
 * directly into the function prologue, so it has no issue probing ftrace internals.
 *
 * Two kprobes are installed:
 *
 *   1. ftrace_set_filter_ip — fires when a caller registers a specific address
 *      as an ftrace filter target. This is the call that says "hook THIS function".
 *      We inspect both the target address (what is being hooked) and the ftrace_ops
 *      callback address (who will run when the hook fires). If either resolves to
 *      an address outside known kernel/module text, or if the target is on one of
 *      the two watchlists, an event is logged.
 *
 *   2. register_ftrace_function — fires when a caller activates a fully-configured
 *      ftrace_ops. A rootkit could bypass ftrace_set_filter_ip by constructing an
 *      ops struct manually and jumping straight to register_ftrace_function. This
 *      second probe catches that case by inspecting ops->func directly.
 *
 * Self-detection avoidance:
 * Both handlers check whether the call originates from our own init/exit path.
 * Rather than a shared atomic flag (which has an SMP race window on multi-core
 * systems), we store the task_struct pointer of the registering task and compare
 * it against current in each handler. Because current is per-CPU and the init
 * path is synchronous, this comparison is inherently race-free.
 *
 * Watchlists:
 * Two tiers of coverage are maintained:
 *
 *   known_rootkit_hooks[] — the exact 13 functions hooked by the Singularity
 *     rootkit's bpf_hook.c. A match here emits BPF_HOOK_SEV_ALERT.
 *
 *   suspicious_hooks[] — functions not confirmed in this specific rootkit but
 *     that are high-value targets for BPF-based evasion. A match here emits
 *     BPF_HOOK_SEV_SUSPICIOUS.
 *
 * An ops->func address that does not resolve to any kernel symbol (i.e.
 * sprint_symbol_no_offset returns a raw hex string) is treated as
 * BPF_HOOK_SEV_CRITICAL regardless of the target function, because a legitimate
 * kernel subsystem will always have its callback in the symbol table.
 *
 * Key differences from ftrace-based detectors:
 * - Uses struct kprobe + register_kprobe() instead of struct ftrace_ops +
 *   ftrace_set_filter_ip() + register_ftrace_function()
 * - Handler signature is kprobe's pre_handler(struct kprobe *, struct pt_regs *)
 *   instead of ftrace's callback(ip, parent_ip, ftrace_ops *, ftrace_regs *)
 * - Reads function arguments via PHOTON_RING_KPROBE_GET_ARG(regs, N) which works
 *   on pt_regs, instead of PHOTON_RING_GET_ARG(fregs, N) which works on ftrace_regs
 * - Both macros live in photon_ring_arch.h and are portable across architectures
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/bpf_hook_detector.h"
#include "../include/event_manager.h"

/* -------------------------------------------------------------------------
 * Watchlists
 * -------------------------------------------------------------------------
 *
 * Tier 1: confirmed hooks from the Singularity rootkit's bpf_hook.c.
 * Every entry here maps 1:1 to a HOOK() macro in that file's hooks[] array.
 * A match emits BPF_HOOK_SEV_ALERT.
 */
static const char * const known_rootkit_hooks[] = {
    "bpf_iter_run_prog",
    "bpf_seq_write",
    "bpf_seq_printf",
    "bpf_ringbuf_output",
    "bpf_ringbuf_reserve",
    "bpf_ringbuf_submit",
    "bpf_map_lookup_elem",
    "bpf_map_update_elem",
    "perf_event_output",
    "perf_trace_run_bpf_submit",
    "__bpf_prog_run",
    "__x64_sys_bpf",
    "__ia32_sys_bpf",
};

#define KNOWN_ROOTKIT_HOOKS_SIZE \
    (sizeof(known_rootkit_hooks) / sizeof(known_rootkit_hooks[0]))

/*
 * Tier 2: high-value BPF/security functions not confirmed in this specific
 * rootkit but that are common targets for BPF-based evasion and privilege
 * escalation. A match emits BPF_HOOK_SEV_SUSPICIOUS.
 */
static const char * const suspicious_hooks[] = {
    "bpf_check",
    "bpf_prog_load",
    "security_bpf",
    "security_bpf_map",
    "security_bpf_prog",
    "bpf_map_get_info_by_fd",
    "bpf_prog_get_info_by_fd",
    "bpf_trampoline_link_prog",
    "bpf_tracing_prog_attach",
    "perf_event_attach_bpf_prog",
};

#define SUSPICIOUS_HOOKS_SIZE \
    (sizeof(suspicious_hooks) / sizeof(suspicious_hooks[0]))

/* -------------------------------------------------------------------------
 * Self-detection avoidance
 * -------------------------------------------------------------------------
 *
 * We store the task_struct pointer of the init/exit task while our own
 * kprobes are being registered or unregistered. The handlers skip any call
 * that originates from that exact task.
 *
 * This is race-free on SMP: current is per-CPU, the init path runs on a
 * single task, and we only suppress events from that one task pointer.
 * A shared atomic flag would have a window between the store and the
 * register_kprobe return during which another CPU could read the flag as
 * clear; comparing task pointers has no such window.
 *
 * The pointer is written under no lock because:
 *   - writes happen only from module init/exit (single-threaded path)
 *   - reads in handlers only compare, they do not dereference the pointer
 *   - a stale read is safe: the worst case is a missed suppression of one
 *     of our own setup calls, which just logs a false positive event
 */
static struct task_struct *g_init_task = NULL;

/* -------------------------------------------------------------------------
 * Shared helper: classify a symbol name and fill bpf_hook_event_data
 * -------------------------------------------------------------------------
 *
 * ops_callback_symbol is considered "anonymous" (unresolved) when
 * sprint_symbol_no_offset cannot find a symbol and returns a raw hex string.
 * The kernel's sprint_symbol_no_offset writes "0x<hex>" in that case, so
 * checking the first two characters is sufficient.
 */
static bool symbol_is_anonymous(const char *sym)
{
    return (sym[0] == '0' && sym[1] == 'x');
}

/*
 * lookup_watchlist_severity - return the severity for a target symbol name.
 *
 * Returns BPF_HOOK_SEV_ALERT if the name is in known_rootkit_hooks[],
 * BPF_HOOK_SEV_SUSPICIOUS if it is in suspicious_hooks[], or
 * BPF_HOOK_SEV_INFO otherwise.
 */
static u8 lookup_watchlist_severity(const char *name)
{
    int i;

    for (i = 0; i < KNOWN_ROOTKIT_HOOKS_SIZE; i++) {
        if (strcmp(name, known_rootkit_hooks[i]) == 0)
            return BPF_HOOK_SEV_ALERT;
    }

    for (i = 0; i < SUSPICIOUS_HOOKS_SIZE; i++) {
        if (strcmp(name, suspicious_hooks[i]) == 0)
            return BPF_HOOK_SEV_SUSPICIOUS;
    }

    return BPF_HOOK_SEV_INFO;
}

/*
 * build_and_log_event - populate a bpf_hook_event_data struct and emit it.
 *
 * @target_ip:     address that ftrace will hook
 * @ops:           the ftrace_ops being registered (may be NULL for the
 *                 register_ftrace_function probe path when ops->func is
 *                 inspected directly)
 * @ops_func:      ops->func pointer (extracted before calling this helper
 *                 so the register_ftrace_function path can pass it directly)
 * @hook_source:   BPF_HOOK_SRC_SET_FILTER or BPF_HOOK_SRC_REGISTER_FN
 *
 * Does not log BPF_HOOK_SEV_INFO events unless the ops callback is anonymous,
 * keeping the event stream free of noise from legitimate kernel activity.
 */
static void build_and_log_event(unsigned long target_ip,
                                unsigned long ops_func,
                                u8 hook_source)
{
    struct bpf_hook_event_data ev;
    u8 severity;

    memset(&ev, 0, sizeof(ev));

    /* resolve target address to a symbol name */
    sprint_symbol_no_offset(ev.target_symbol, target_ip);
    ev.target_addr = target_ip;

    /* resolve the ops callback address */
    if (ops_func) {
        sprint_symbol_no_offset(ev.ops_callback_symbol, ops_func);
        ev.ops_callback_addr = ops_func;
    } else {
        strncpy(ev.ops_callback_symbol, "<null>",
                sizeof(ev.ops_callback_symbol) - 1);
    }

    /* caller identity */
    strncpy(ev.caller_comm, current->comm, sizeof(ev.caller_comm) - 1);
    ev.caller_pid = current->pid;
    ev.hook_source = hook_source;

    /*
     * Determine severity.
     *
     * An anonymous callback address is CRITICAL regardless of the target
     * because no legitimate kernel subsystem has its ftrace callback in
     * unmapped/unsymbolised memory.  Check this first so it takes precedence
     * over the watchlist result.
     */
    if (ops_func && symbol_is_anonymous(ev.ops_callback_symbol)) {
        severity = BPF_HOOK_SEV_CRITICAL;
    } else {
        severity = lookup_watchlist_severity(ev.target_symbol);
    }

    ev.severity = severity;

    /* suppress INFO events to avoid flooding the ring buffer with noise
     * from legitimate kernel module activity */
    if (severity == BPF_HOOK_SEV_INFO)
        return;

    switch (severity) {
    case BPF_HOOK_SEV_CRITICAL:
        printk(KERN_ALERT
               "[PHOTON RING] CRITICAL *** ftrace hook with anonymous callback "
               "%s -> %s by '%s' (PID %d)\n",
               ev.ops_callback_symbol, ev.target_symbol,
               ev.caller_comm, ev.caller_pid);
        break;
    case BPF_HOOK_SEV_ALERT:
        printk(KERN_ALERT
               "[PHOTON RING] ALERT *** ftrace hook on confirmed rootkit target: "
               "%s (addr %lx) by '%s' (PID %d)\n",
               ev.target_symbol, ev.target_addr,
               ev.caller_comm, ev.caller_pid);
        break;
    case BPF_HOOK_SEV_SUSPICIOUS:
        printk(KERN_WARNING
               "[PHOTON RING] SUSPICIOUS ftrace hook on watchlisted function: "
               "%s (addr %lx) by '%s' (PID %d)\n",
               ev.target_symbol, ev.target_addr,
               ev.caller_comm, ev.caller_pid);
        break;
    default:
        break;
    }

    photon_log_event(PHOTON_EVENT_BPF_REG,
                     PHOTON_DETECTOR_BPF,
                     &ev,
                     sizeof(ev));
}

/* -------------------------------------------------------------------------
 * Kprobe 1: ftrace_set_filter_ip
 * -------------------------------------------------------------------------
 *
 * Signature:
 *   int ftrace_set_filter_ip(struct ftrace_ops *ops,
 *                            unsigned long ip,
 *                            int remove,
 *                            int reset);
 *
 * arg 0 = ops   (struct ftrace_ops *)
 * arg 1 = ip    (the address being added or removed from the filter)
 * arg 2 = remove (non-zero means the ip is being removed, not added)
 * arg 3 = reset
 *
 * We only care about additions (remove == 0).  For additions we:
 *   1. Check target_ip (arg 1) against both watchlists.
 *   2. Dereference ops->func to check whether the callback is anonymous.
 *   3. Emit an event if severity > INFO.
 */
static struct kprobe kp_set_filter;

static int handler_set_filter(struct kprobe *p, struct pt_regs *regs)
{
    struct ftrace_ops *ops;
    unsigned long target_ip;
    unsigned long remove;
    unsigned long ops_func = 0;

    /* skip calls from our own init/exit */
    if (current == g_init_task)
        return 0;

    ops       = (struct ftrace_ops *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    target_ip = PHOTON_RING_KPROBE_GET_ARG(regs, 1);
    remove    = PHOTON_RING_KPROBE_GET_ARG(regs, 2);

    /* only detect additions */
    if (remove)
        return 0;

    /* safely read ops->func — ops comes from the caller and could in theory
     * be a bad pointer, but in practice register_kprobe validates it before
     * we ever see it. A NULL check is sufficient here. */
    if (ops && ops->func)
        ops_func = (unsigned long)ops->func;

    build_and_log_event(target_ip, ops_func, BPF_HOOK_SRC_SET_FILTER);

    return 0;
}

/* -------------------------------------------------------------------------
 * Kprobe 2: register_ftrace_function
 * -------------------------------------------------------------------------
 *
 * Signature:
 *   int register_ftrace_function(struct ftrace_ops *ops);
 *
 * arg 0 = ops (struct ftrace_ops *)
 *
 * A rootkit can construct an ftrace_ops manually (e.g. by writing the filter
 * hash directly) and call register_ftrace_function without going through
 * ftrace_set_filter_ip. This probe catches that path by inspecting ops->func.
 *
 * We cannot check the target function name here because register_ftrace_function
 * does not take a target address — the filter was already configured.  We
 * therefore focus entirely on whether ops->func is anonymous, which is the
 * highest-signal indicator of a rootkit callback regardless of target.
 *
 * For non-anonymous callbacks we still emit a SUSPICIOUS/ALERT event when
 * ops->func resolves to a name that matches a watchlisted symbol — this catches
 * a rootkit that was careless enough to leave its hook handler in the symbol
 * table (unlikely but possible during development/testing).
 */
static struct kprobe kp_register_fn;

static int handler_register_fn(struct kprobe *p, struct pt_regs *regs)
{
    struct ftrace_ops *ops;
    unsigned long ops_func = 0;
    char ops_func_sym[KSYM_SYMBOL_LEN];
    u8 severity;

    /* skip calls from our own init/exit */
    if (current == g_init_task)
        return 0;

    ops = (struct ftrace_ops *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
    if (!ops || !ops->func)
        return 0;

    ops_func = (unsigned long)ops->func;
    sprint_symbol_no_offset(ops_func_sym, ops_func);

    /*
     * Anonymous callback address: emit CRITICAL regardless of target.
     * Named callback on a watchlisted symbol: emit the appropriate severity.
     * Everything else: suppress to avoid noise.
     */
    if (symbol_is_anonymous(ops_func_sym)) {
        severity = BPF_HOOK_SEV_CRITICAL;
    } else {
        severity = lookup_watchlist_severity(ops_func_sym);
    }

    if (severity == BPF_HOOK_SEV_INFO)
        return 0;

    /*
     * We don't have the target ip here, so pass 0 for target_addr.
     * build_and_log_event will resolve it to an empty symbol string which
     * userspace can use to identify that this came from the register path.
     */
    build_and_log_event(0, ops_func, BPF_HOOK_SRC_REGISTER_FN);

    return 0;
}

/* -------------------------------------------------------------------------
 * Init / exit
 * -------------------------------------------------------------------------*/

int bpf_hook_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing BPF hook detector...\n");

    /*
     * Record the current task so both handlers can suppress events that
     * originate from our own registration calls below.
     */
    g_init_task = current;

    /* --- Kprobe 1: ftrace_set_filter_ip --- */
    memset(&kp_set_filter, 0, sizeof(kp_set_filter));
    kp_set_filter.symbol_name = "ftrace_set_filter_ip";
    kp_set_filter.pre_handler = handler_set_filter;

    ret = register_kprobe(&kp_set_filter);
    if (ret) {
        printk(KERN_ERR
               "[PHOTON RING] failed to register kprobe for ftrace_set_filter_ip: %d\n",
               ret);
        g_init_task = NULL;
        return ret;
    }

    printk(KERN_INFO
           "[PHOTON RING] probing ftrace_set_filter_ip at %px\n",
           kp_set_filter.addr);

    /* --- Kprobe 2: register_ftrace_function --- */
    memset(&kp_register_fn, 0, sizeof(kp_register_fn));
    kp_register_fn.symbol_name = "register_ftrace_function";
    kp_register_fn.pre_handler = handler_register_fn;

    ret = register_kprobe(&kp_register_fn);
    if (ret) {
        printk(KERN_ERR
               "[PHOTON RING] failed to register kprobe for register_ftrace_function: %d\n",
               ret);
        /* clean up the first probe before returning the error */
        unregister_kprobe(&kp_set_filter);
        g_init_task = NULL;
        return ret;
    }

    printk(KERN_INFO
           "[PHOTON RING] probing register_ftrace_function at %px\n",
           kp_register_fn.addr);

    /* registration complete — clear the suppression pointer */
    g_init_task = NULL;

    printk(KERN_INFO
           "[PHOTON RING] BPF hook detector active: "
           "%zu confirmed rootkit targets, %zu suspicious targets\n",
           KNOWN_ROOTKIT_HOOKS_SIZE, SUSPICIOUS_HOOKS_SIZE);

    return 0;
}

void bpf_hook_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing BPF hook detector...\n");

    /*
     * Suppress events from our own unregister calls, same logic as init.
     */
    g_init_task = current;

    unregister_kprobe(&kp_set_filter);
    unregister_kprobe(&kp_register_fn);

    g_init_task = NULL;

    printk(KERN_INFO "[PHOTON RING] BPF hook detector removed\n");
}