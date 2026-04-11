#ifndef HIDING_CHDIR_DETECTOR_H
#define HIDING_CHDIR_DETECTOR_H

/**
 * hiding_chdir_detector_init - Initialize the chdir hiding detector
 *
 * Hooks the chdir syscall to detect rootkits that block access
 * to certain directories by returning -ENOENT.
 *
 * Returns: 0 on success, negative error code on failure
 */
int hiding_chdir_detector_init(void);

/**
 * hiding_chdir_detector_exit - Cleanup the chdir hiding detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void hiding_chdir_detector_exit(void);

#endif /* HIDING_CHDIR_DETECTOR_H */
