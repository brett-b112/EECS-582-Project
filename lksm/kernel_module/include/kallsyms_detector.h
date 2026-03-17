#ifndef KALLSYMS_DETECTOR_H
#define KALLSYMS_DETECTOR_H

/*
 * Threat-tier flags encoded in kprobe_event_data.flags for events
 * emitted by the kallsyms detector.  Userspace can test these bits
 * to triage alerts without re-parsing the symbol name.
 *
 *  CRITICAL    — looking up this symbol from an unknown module is
 *                unambiguously hostile (e.g. "tainted_mask",
 *                "sys_call_table").
 *
 *  HOOK_TARGET — the symbol is a common IPMODIFY hook destination;
 *                the lookup almost certainly precedes hook installation
 *                (e.g. "filldir64", "commit_creds").
 *
 *  AUDIT       — noteworthy for correlation but not conclusive alone
 *                (e.g. "ftrace_ops_list", "module_alloc").
 */
#define KALLSYMS_FLAG_CRITICAL     0x10u
#define KALLSYMS_FLAG_HOOK_TARGET  0x20u
#define KALLSYMS_FLAG_AUDIT        0x40u

/**
 * kallsyms_detector_init - register the kallsyms_lookup_name ftrace hook
 *
 * Installs an observer-only (no IPMODIFY) ftrace hook on
 * kallsyms_lookup_name and begins classifying every lookup that
 * originates outside of this module.
 *
 * Requires kprobe_detector_init() to have already run successfully,
 * as it obtains the kallsyms_lookup_name address via
 * kprobe_detector_get_kallsyms_addr().
 *
 * Returns 0 on success, -ENOENT if the address is not yet available,
 * or a negative error code from the ftrace registration path.
 */
int kallsyms_detector_init(void);

/**
 * kallsyms_detector_exit - remove the kallsyms_lookup_name ftrace hook
 */
void kallsyms_detector_exit(void);

#endif /* KALLSYMS_DETECTOR_H */