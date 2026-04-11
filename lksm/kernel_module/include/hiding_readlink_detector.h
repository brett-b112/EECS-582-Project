#ifndef HIDING_READLINK_DETECTOR_H
#define HIDING_READLINK_DETECTOR_H

/**
 * hiding_readlink_detector_init - Initialize the readlink hiding detector
 *
 * Hooks the readlink syscall to detect rootkits that return -ENOENT
 * for specific paths to hide module symlinks.
 *
 * Returns: 0 on success, negative error code on failure
 */
int hiding_readlink_detector_init(void);

/**
 * hiding_readlink_detector_exit - Cleanup the readlink hiding detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void hiding_readlink_detector_exit(void);

#endif /* HIDING_READLINK_DETECTOR_H */
