#ifndef KPROBE_DETECTOR_H
#define KPROBE_DETECTOR_H

#include <linux/ftrace.h>

/**
 * kprobe_detector_init - Initialize the kprobe detector
 * 
 * Sets up ftrace hooks to monitor kprobe registrations
 * 
 * Returns: 0 on success, negative error code on failure
 */
int kprobe_detector_init(void);

/**
 * kprobe_detector_exit - Cleanup the kprobe detector
 * 
 * Removes ftrace hooks and cleans up resources
 */
void kprobe_detector_exit(void);

#endif /* KPROBE_DETECTOR_H */