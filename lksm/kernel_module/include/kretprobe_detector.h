#ifndef KRETPROBE_DETECTOR_H
#define KRETPROBE_DETECTOR_H

/*
 * kretprobe_detector.h — Photon Ring
 *
 * Covers the two kprobe registration paths that kprobe_detector misses:
 *
 *   register_kretprobe(struct kretprobe *rp)
 *     Registers a return probe on a function.  Internally it calls
 *     register_kprobe() on the embedded kp member, but by the time that
 *     inner call fires the symbol_name pointer has already been cleared and
 *     only kp->addr is valid — so kprobe_detector sees the address but not
 *     the name.  Hooking register_kretprobe directly gives us:
 *       - rp->kp.symbol_name  (original name, before resolution)
 *       - rp->handler         (return handler callback address)
 *       - rp->entry_handler   (optional entry handler callback address)
 *       - rp->maxactive       (concurrency limit — abnormally high values
 *                              suggest an attempt to intercept every in-flight
 *                              call simultaneously)
 *
 *   register_kprobes(struct kprobe **kps, int num)
 *     Batch registration.  kprobe_detector catches each element because
 *     register_kprobes calls register_kprobe in a loop, but we lose the
 *     batch size — a rootkit registering a large array at once is higher
 *     signal than individual registrations.  Hooking register_kprobes
 *     gives us num so userspace can correlate a burst of probes that
 *     arrived atomically.
 *
 * Both hooks use ftrace (PHOTON_RING_FTRACE_FLAGS / PHOTON_RING_GET_ARG)
 * because register_kretprobe and register_kprobes are not ftrace
 * infrastructure — there is no self-hooking problem here.
 *
 * Suspicious-symbol matching
 * --------------------------
 * The same three-tier watchlist used by kallsyms_detector is applied to
 * every symbol name seen at registration time:
 *
 *   KRETPROBE_FLAG_CRITICAL    — unambiguously hostile targets
 *   KRETPROBE_FLAG_HOOK_TARGET — common rootkit redirection targets
 *   KRETPROBE_FLAG_AUDIT       — noteworthy for correlation
 *
 * An anonymous handler address (sprint_symbol_no_offset returns "0x...")
 * is always KRETPROBE_FLAG_CRITICAL regardless of target symbol.
 *
 * High maxactive
 * --------------
 * A maxactive value above KRETPROBE_MAXACTIVE_THRESHOLD is flagged
 * independently of the symbol name, because it suggests the probe is
 * designed to intercept every concurrent invocation of the target —
 * a pattern used by rootkits that need to filter return values for all
 * callers simultaneously (e.g. hiding PIDs from getdents64).
 */

/*
 * Payload flags — now defined in event_manager.h as PROBE_FLAG_* and shared
 * across all probe-category detectors:
 *   PROBE_FLAG_WATCHLISTED   — target symbol on photon_watchlist
 *   PROBE_FLAG_ANON_HANDLER  — handler address outside the symbol table
 *   PROBE_FLAG_HIGH_ACTIVE   — maxactive above KRETPROBE_MAXACTIVE_THRESHOLD
 *   PROBE_FLAG_BATCH         — arrived via register_kprobes() batch call
 *
 * severity is set in the event envelope by photon_log_event(), not in the
 * payload struct.
 */

/*
 * maxactive values above this threshold are suspicious.
 * The kernel default is max(10, 2*NR_CPUS).  On a 64-core machine that is
 * 128.  A rootkit that wants to intercept every concurrent getdents64 call
 * typically sets maxactive to 0 (= use default) or a very large explicit
 * value.  512 is a conservative threshold that will not fire on any
 * realistic legitimate use.
 */
#define KRETPROBE_MAXACTIVE_THRESHOLD 512

/**
 * kretprobe_detector_init - register ftrace hooks on register_kretprobe
 *                           and register_kprobes
 *
 * Returns 0 on success, negative error code on failure.
 * Does not depend on kprobe_detector having run first.
 */
int kretprobe_detector_init(void);

/**
 * kretprobe_detector_exit - remove ftrace hooks
 */
void kretprobe_detector_exit(void);

#endif /* KRETPROBE_DETECTOR_H */