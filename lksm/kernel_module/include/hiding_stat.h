#ifndef HIDING_STAT_H
#define HIDING_STAT_H

#include <linux/ftrace.h>


int hiding_stat_init(void);
void hiding_stat_exit(void);
extern int hooks_installed;

#endif