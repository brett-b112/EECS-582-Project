// hiding_chdir_detector.c
// Detects rootkits that hook the chdir syscall to block access to hidden
// directories by returning -ENOENT (e.g. Singularity's hiding_chdir_init)
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include "../include/photon_ring_arch.h"
#include "../include/hiding_chdir_detector.h"

static struct kprobe kp;

/*
 * The Singularity rootkit hooks __x64_sys_chdir to return -ENOENT for
 * directories it wants to hide. We use a kprobe on __arm64_sys_chdir
 * (or __x64_sys_chdir on x86) since these symbols are not exported
 * and cannot be hooked via ftrace directly.
 *
 * We watch for chdir calls that target sensitive or unusual paths --
 * particularly /proc entries, hidden directories, and paths commonly
 * used by rootkits to store their files.
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    const char __user *filename;
    char buf[256];
    long len;

    filename = (const char __user *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);

    if (!filename)
        return 0;

    len = strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (len <= 0)
        return 0;
    buf[len] = '\0';

    /* Flag chdir to paths commonly targeted by rootkits */
    if (strstr(buf, "/proc/") != NULL ||
        strstr(buf, "/.hidden") != NULL ||
        strstr(buf, "/dev/shm/") != NULL) {
        printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** chdir to sensitive path '%s'"
               " by process '%s' (PID %d)."
               " Monitoring for chdir-hiding rootkit activity!\n",
               buf, current->comm, current->pid);
    }

    return 0;
}

int hiding_chdir_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing hiding_chdir detector...\n");

    /*
     * Use kprobe to hook the sys_chdir entry point by symbol name.
     * The kernel will resolve the correct architecture-specific symbol.
     */
#if defined(__aarch64__)
    kp.symbol_name = "__arm64_sys_chdir";
#elif defined(__x86_64__)
    kp.symbol_name = "__x64_sys_chdir";
#else
    kp.symbol_name = "sys_chdir";
#endif
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] hiding_chdir: failed to register kprobe: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully probed %s at: %px\n",
           kp.symbol_name, kp.addr);
    printk(KERN_INFO "[PHOTON RING] now monitoring for chdir-hiding behavior...\n");

    return 0;
}

void hiding_chdir_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing hiding_chdir detector...\n");

    unregister_kprobe(&kp);

    printk(KERN_INFO "[PHOTON RING] hiding_chdir detector removed\n");
}
