#ifndef BECOME_ROOT_DETECTOR_H
#define BECOME_ROOT_DETECTOR_H

#include <linux/ftrace.h>

/**
 * become_root_detector_init - Initialize the become_root detector
 *
 * Sets up ftrace hook on commit_creds to detect privilege escalation
 *
 * Returns: 0 on success, negative error code on failure
 */
int become_root_detector_init(void);

/**
 * become_root_detector_exit - Cleanup the become_root detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void become_root_detector_exit(void);

#endif /* BECOME_ROOT_DETECTOR_H */