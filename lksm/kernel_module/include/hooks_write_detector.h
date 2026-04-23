#ifndef HOOKS_WRITE_DETECTOR_H
#define HOOKS_WRITE_DETECTOR_H

/**
 * hooks_write_detector_init - Initialize the write hook detector
 *
 * Hooks ksys_write to detect rootkits that intercept write syscalls
 * to filter sensitive keywords from output or block writes to
 * ftrace control files.
 *
 * Returns: 0 on success, negative error code on failure
 */
int hooks_write_detector_init(void);

/**
 * hooks_write_detector_exit - Cleanup the write hook detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void hooks_write_detector_exit(void);

#endif /* HOOKS_WRITE_DETECTOR_H */
