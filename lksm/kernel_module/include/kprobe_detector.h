#ifndef KPROBE_DETECTOR_H
#define KPROBE_DETECTOR_H

#include <linux/ftrace.h>

/* kprobe-specific event data */
struct kprobe_event_data {
    char symbol_name[64];
    unsigned long addr;
    u32 flags;
    u8 is_suspicious;
} __attribute__((packed));

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