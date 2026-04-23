
#ifndef RESET_TAINTED_DETECTOR_H
#define RESET_TAINTED_DETECTOR_H

#include <linux/ftrace.h>

/**
 * reset_tainted_detector_init initializes the reset_tainted detector
 *
 * Three detection vectors:
 *   A. ftrace hook on kthread_create_on_node: flags suspicious thread names
 *      (like "zer0t") at the moment of creation.
 *   B. Periodic workqueue (every 5s): resolves tainted_mask at init, records
 *      the baseline, and alerts when bits are unexpectedly cleared to 0.
 *   C. Periodic task scan (every 10s): walks init_task.tasks looking for
 *      threads with suspicious names that may be hidden from /proc.
 */
int reset_tainted_detector_init(void);

/**
 * reset_tainted_detector_exit is to cleanup the reset_tainted detector
 *
 * Removes the ftrace hook and cancels both workqueues
 */
void reset_tainted_detector_exit(void);

#endif /* RESET_TAINTED_DETECTOR_H */
