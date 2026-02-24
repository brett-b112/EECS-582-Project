#ifndef HIDING_STAT_H
#define HIDING_STAT_H

#include <linux/ftrace.h>

/*
 * Initializes the hiding_stat module.
 * 
 * Returns:
 *   0 on success
 *   Negative error code on failure.
 */
int hiding_stat_init(void);

/*
 * Cleans up and unloads the hiding_stat module.
 * 
 * This function should reverse everything done in hiding_stat_init(),
 * such as removing hooks and freeing allocated resources.
 */

void hiding_stat_exit(void);
extern int hooks_installed;

#endif /* HIDING_STAT_H */