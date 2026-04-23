#ifndef CLEAR_TAINT_DMESG_DETECTOR_H
#define CLEAR_TAINT_DMESG_DETECTOR_H

/**
 * clear_taint_dmesg_detector_init - Initialize the dmesg taint clearing detector
 *
 * Hooks do_syslog and read-related syscalls to detect rootkits that
 * filter kernel log output to hide evidence of hooking, taint flags,
 * and module presence.
 *
 * Returns: 0 on success, negative error code on failure
 */
int clear_taint_dmesg_detector_init(void);

/**
 * clear_taint_dmesg_detector_exit - Cleanup the dmesg taint clearing detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void clear_taint_dmesg_detector_exit(void);

#endif /* CLEAR_TAINT_DMESG_DETECTOR_H */
