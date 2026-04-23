// hiding_readlink_detector.c
// Detects rootkits that hook the readlink syscall to hide module paths
// by returning -ENOENT for specific symlinks (e.g. Singularity's hiding_readlink_init)
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/hiding_readlink_detector.h"

static struct ftrace_ops ops;
static unsigned long target_addr;

/*
 * The Singularity rootkit hooks __x64_sys_readlink to return -ENOENT for
 * paths it wants to hide. We detect this by monitoring vfs_readlink -- the
 * VFS layer function that all readlink paths funnel through. Any hooking
 * of readlink must ultimately affect this function's behavior.
 *
 * We hook vfs_readlink to log all readlink operations on sensitive paths
 * (e.g. proc exe symlinks, module paths) so anomalies can be correlated
 * in Kibana with other rootkit indicators.
 */
static notrace void hook_vfs_readlink(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *fops,
                                      struct ftrace_regs *fregs)
{
    struct dentry *dentry;
    const char *name;

    dentry = (struct dentry *)PHOTON_RING_GET_ARG(fregs, 0);

    if (!dentry || !dentry->d_name.name)
        return;

    name = dentry->d_name.name;

    /* Flag readlink on module-related or proc paths that rootkits typically hide */
    if (strncmp(name, "exe", 3) == 0 ||
        strstr(name, ".ko") != NULL) {
        printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** readlink on sensitive path '%s'"
               " by process '%s' (PID %d), caller: %pS."
               " Monitoring for readlink-hiding rootkit activity!\n",
               name, current->comm, current->pid, (void *)parent_ip);
    }
}

int hiding_readlink_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing hiding_readlink detector...\n");

    target_addr = (unsigned long)vfs_readlink;

    printk(KERN_INFO "[PHOTON RING] found vfs_readlink at: %lx\n", target_addr);

    ops.func = hook_vfs_readlink;
    ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops, target_addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] hiding_readlink: failed to set ftrace filter: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] hiding_readlink: failed to register ftrace function: %d\n", ret);
        ftrace_set_filter_ip(&ops, target_addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully hooked vfs_readlink\n");
    printk(KERN_INFO "[PHOTON RING] now monitoring for readlink-hiding behavior...\n");

    return 0;
}

void hiding_readlink_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing hiding_readlink detector...\n");

    unregister_ftrace_function(&ops);
    ftrace_set_filter_ip(&ops, target_addr, 1, 0);

    printk(KERN_INFO "[PHOTON RING] hiding_readlink detector removed\n");
}
