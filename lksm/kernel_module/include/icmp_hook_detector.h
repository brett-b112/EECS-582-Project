
#ifndef ICMP_HOOK_DETECTOR_H
#define ICMP_HOOK_DETECTOR_H

#include <linux/ftrace.h>

/**
 * icmp_hook_detector_init - Initialize the ICMP hook detector
 *
 * Resolves the address of icmp_rcv, then hooks ftrace_set_filter_ip to catch
 * rootkit attempts to install hooks on it (e.g. Singularity's ICMP backdoor
 * which triggers a reverse shell on magic ICMP sequence numbers).
 *
 * Returns: 0 on success, negative error code on failure
 */
int icmp_hook_detector_init(void);

/**
 * icmp_hook_detector_exit - Cleanup the ICMP hook detector
 *
 * Removes the kprobe on ftrace_set_filter_ip.
 */
void icmp_hook_detector_exit(void);

#endif /* ICMP_HOOK_DETECTOR_H */
