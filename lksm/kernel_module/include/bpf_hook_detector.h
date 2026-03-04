#ifndef BPF_HOOK_DETECTOR_H
#define BPF_HOOK_DETECTOR_H

#include <linux/ftrace.h>

/**
 * bpf_hook_detector_init - Initialize the BPF hook detector
 *
 * Sets up ftrace hooks to monitor ftrace_set_filter_ip calls
 * targeting BPF-critical kernel functions
 *
 * Returns: 0 on success, negative error code on failure
 */
int bpf_hook_detector_init(void);

/**
 * bpf_hook_detector_exit - Cleanup the BPF hook detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void bpf_hook_detector_exit(void);

#endif /* BPF_HOOK_DETECTOR_H */
