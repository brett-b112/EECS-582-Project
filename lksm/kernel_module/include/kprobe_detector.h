#ifndef KPROBE_DETECTOR_H
#define KPROBE_DETECTOR_H

#include <linux/ftrace.h>

/**
 * kprobe_detector_init - Initialize the kprobe detector
 *
 * Sets up ftrace hooks to monitor kprobe registrations.
 * As a side effect, resolves and caches the runtime address of
 * kallsyms_lookup_name via the kprobe bootstrap technique so that
 * other detectors (e.g. kallsyms_detector) can obtain it without
 * repeating the bootstrap independently.
 *
 * Must be called before kallsyms_detector_init.
 *
 * Returns: 0 on success, negative error code on failure
 */
int kprobe_detector_init(void);

/**
 * kprobe_detector_exit - Cleanup the kprobe detector
 *
 * Removes ftrace hooks and cleans up resources.
 */
void kprobe_detector_exit(void);

/**
 * kprobe_detector_get_kallsyms_addr - return the cached address of
 * kallsyms_lookup_name resolved during kprobe_detector_init.
 *
 * Returns 0 if kprobe_detector_init has not been called yet or if
 * resolution failed.
 */
unsigned long kprobe_detector_get_kallsyms_addr(void);

#endif /* KPROBE_DETECTOR_H */