// hooks_write_detector.c
// Detects rootkits that hook write syscalls to filter sensitive keywords
// from output or block writes to ftrace control files
// (e.g. Singularity's hooks_write_init)
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include "../include/photon_ring_arch.h"
#include "../include/hooks_write_detector.h"

static struct kprobe kp;

/*
 * The Singularity rootkit hooks ~26 write-related syscalls to:
 * 1. Filter keywords ("taint", "singularity") from output buffers
 * 2. Intercept writes to ftrace_enabled/tracing_on control files
 * 3. Block io_uring for processes with ftrace file descriptors
 *
 * We detect this by monitoring vfs_write via kprobe (since it is not
 * exported on modern kernels). We flag writes to sensitive kernel
 * control files (ftrace, tracing) which rootkits commonly target.
 *
 * vfs_write signature: ssize_t vfs_write(struct file *file,
 *                                        const char __user *buf,
 *                                        size_t count, loff_t *pos)
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    struct dentry *dentry;
    const char *name;

    file = (struct file *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);

    if (!file)
        return 0;

    dentry = file->f_path.dentry;
    if (!dentry || !dentry->d_name.name)
        return 0;

    name = dentry->d_name.name;

    /* Flag writes to ftrace/tracing control files */
    if (strcmp(name, "ftrace_enabled") == 0 ||
        strcmp(name, "tracing_on") == 0 ||
        strcmp(name, "current_tracer") == 0 ||
        strcmp(name, "set_ftrace_filter") == 0 ||
        strcmp(name, "trace_pipe") == 0) {
        printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** write to ftrace control file '%s'"
               " by process '%s' (PID %d)."
               " Possible write-hook rootkit tampering!\n",
               name, current->comm, current->pid);
    }

    return 0;
}

int hooks_write_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing hooks_write detector...\n");

    kp.symbol_name = "vfs_write";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] hooks_write: failed to register kprobe: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully probed vfs_write at: %px\n", kp.addr);
    printk(KERN_INFO "[PHOTON RING] now monitoring for write-hook rootkit behavior...\n");

    return 0;
}

void hooks_write_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing hooks_write detector...\n");

    unregister_kprobe(&kp);

    printk(KERN_INFO "[PHOTON RING] hooks_write detector removed\n");
}
