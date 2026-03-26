
#ifndef RESET_TAINTED_DETECTOR_H
#define RESET_TAINTED_DETECTOR_H

#include <linux/ftrace.h>

/**
 * reset_tainted_detector_init - Initialize the reset_tainted detector
 *
 * Three detection vectors:
 *   A. ftrace hook on kthread_create_on_node: flags suspicious thread names
 *      (e.g., "zer0t") at the moment of creation.
 *   B. Periodic workqueue (every 5s): resolves tainted_mask at init, records
 *      the baseline, and alerts when bits are unexpectedly cleared to 0.
 *   C. Periodic task scan (every 10s): walks init_task.tasks looking for
 *      threads with suspicious names that may be hidden from /proc.
 *
 * Returns: 0 on success
 */
int reset_tainted_detector_init(void);

/**
 * reset_tainted_detector_exit - Cleanup the reset_tainted detector
 *
 * Removes the ftrace hook and cancels both workqueues.
 */
void reset_tainted_detector_exit(void);

#endif /* RESET_TAINTED_DETECTOR_H */
