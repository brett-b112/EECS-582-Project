#ifndef HIDING_DIRECTORY_H
#define HIDING_DIRECTORY_H

#include <linux/ftrace.h>

// Initiates the hiding_directory module. This will return 0 for empty or -1 if there is a file in path 
int hiding_directory_init(void)


// Cleans up and unloads the hiding directory module 

// The function will reverse the behavior done in hiding_directory_init()

void hiding_directory_exit(void)
#endif /* HIDING_DIRECTORY_H */\