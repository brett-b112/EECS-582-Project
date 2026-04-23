#ifndef FTRACE_DIRECT_DETECTOR_H
#define FTRACE_DIRECT_DETECTOR_H

/*
 * ftrace_direct_detector.h — Photon Ring
 *
 * Covers two ftrace registration paths that bpf_hook_detector misses:
 *
 * 1. ftrace_set_filter / ftrace_set_notrace  (glob/string filter API)
 *    A caller can register ftrace hooks using a symbol-name glob pattern
 *    rather than a specific address.  bpf_hook_detector watches only
 *    ftrace_set_filter_ip (the address-based path).  A rootkit can bypass
 *    that by calling ftrace_set_filter("tcp*_seq_show", ...) instead.
 *    Both functions take (ops, buf, len, reset) — buf is the pattern string.
 *
 * 2. modify_ftrace_direct  (direct-call patching)
 *    Introduced in 5.15, this API lets a caller replace the NOP/call at a
 *    function's ftrace site with a direct unconditional jump to an arbitrary
 *    address — bypassing the normal ftrace_ops dispatch entirely.
 *    register_ftrace_function is never called on this path, so
 *    bpf_hook_detector's second probe does not fire.
 *    modify_ftrace_direct(ip, old_addr, new_addr) atomically swaps the
 *    destination; we log ip (what is being patched) and new_addr (where
 *    execution will jump).
 *
 * Instrumentation method
 * ----------------------
 * All three kprobes target ftrace infrastructure, which ftrace cannot hook
 * itself, so kprobes (INT3/BRK breakpoint) is the correct mechanism here.
 *
 * Self-detection avoidance
 * ------------------------
 * We store the registering task_struct pointer (g_init_task) while our own
 * kprobes are being registered and clear it immediately after.  Handlers
 * skip events from that task.
 *
 * Severity
 * --------
 * All events from this detector are emitted at FTRACE_DIRECT_SEV_CRITICAL.
 * Every intercepted call represents either an anonymous callback (code
 * outside the symbol table) or a direct hook on a watchlisted symbol —
 * both are unambiguously hostile in context.
 */

/*
 * hook_source values are defined in event_manager.h as FTRACE_HOOK_SRC_*.
 * severity is always PHOTON_SEV_CRITICAL for this detector and is set in the
 * envelope by photon_log_event(), not in the payload struct.
 */

/**
 * ftrace_direct_detector_init - register kprobes on the three targets.
 *
 * Returns 0 on success.  Returns a negative error code only if *all*
 * probes fail to install — a partial installation is considered success
 * because each probe is independently useful.
 *
 * Note: modify_ftrace_direct was added in kernel 5.15.  Its probe failing
 * with -ENOENT on older kernels is expected and non-fatal.
 */
int ftrace_direct_detector_init(void);

/**
 * ftrace_direct_detector_exit - unregister all kprobes
 */
void ftrace_direct_detector_exit(void);

#endif /* FTRACE_DIRECT_DETECTOR_H */