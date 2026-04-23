#ifndef LKRG_BYPASS_DETECTOR_H
#define LKRG_BYPASS_DETECTOR_H

/**
 * lkrg_bypass_detector_init - Initialize the LKRG bypass detector
 *
 * Hooks vprintk_emit and call_usermodehelper_exec to detect rootkits
 * that filter LKRG log messages and tamper with usermode helper
 * validation to evade Linux Kernel Runtime Guard.
 *
 * Returns: 0 on success, negative error code on failure
 */
int lkrg_bypass_detector_init(void);

/**
 * lkrg_bypass_detector_exit - Cleanup the LKRG bypass detector
 *
 * Removes ftrace hooks and cleans up resources
 */
void lkrg_bypass_detector_exit(void);

#endif /* LKRG_BYPASS_DETECTOR_H */
