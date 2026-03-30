#ifndef LKRG_BYPASS_H
#define LKRG_BYPASS_H

#include <linux/ftrace.h>

/**
 * lkrg_bypass_init will initialize the lkrg_bypass_init detector
 * 
 * Detector will attempt to disable the LKRG timer and/or monitor tampering with validation structure
 * 
 */
int lkrg_bypass_init(void);

/**
 * cleans up the lkrg_bypass detector
 * 
 * Removes process hook and restores to original state
 */
void lkrg_bypass_exit(void);

#endif /* LKRG_BYPASS_H */