#ifndef TRACE_PID_DETECTOR_H
#define TRACE_PID_DETECTOR_H

/**
 * trace_pid_detector_init - Initialize the trace PID detector
 *
 * Monitors the sched_process_fork tracepoint to detect rootkits
 * that automatically hide child processes of hidden PIDs.
 *
 * Returns: 0 on success, negative error code on failure
 */
int trace_pid_detector_init(void);

/**
 * trace_pid_detector_exit - Cleanup the trace PID detector
 *
 * Removes tracepoint hooks and cleans up resources
 */
void trace_pid_detector_exit(void);

#endif /* TRACE_PID_DETECTOR_H */
