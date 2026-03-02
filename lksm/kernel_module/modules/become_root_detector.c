// photon_ring_become_root_detector.c
// Detects privilege escalation via commit_creds (e.g. Singularity's SpawnRoot)
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include "../include/photon_ring_arch.h"
#include "../include/become_root_detector.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brett");
MODULE_DESCRIPTION("Detect privilege escalation via commit_creds");
MODULE_VERSION("1.0");

static struct ftrace_ops ops;

static notrace void hook_commit_creds(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct ftrace_regs *fregs)
{
    struct cred *new_cred;

    // get first arg (struct cred *new) portably via ftrace_regs
    new_cred = (struct cred *)PHOTON_RING_GET_ARG(fregs, 0);

    if (!new_cred)
        return;

    // check if new credentials grant root (uid 0) to a non-root process
    if (new_cred->uid.val == 0 && current_uid().val != 0) {
        printk(KERN_ALERT "[PHOTON RING] *** PRIVILEGE ESCALATION DETECTED ***\n");
        printk(KERN_ALERT "[PHOTON RING] Process '%s' (PID %d) becoming root via commit_creds!\n",
               current->comm, current->pid);
    }
}

int become_root_detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing become_root detector...\n");

    // get the commit_creds function address
    addr = (unsigned long)commit_creds;

    printk(KERN_INFO "[PHOTON RING] found commit_creds at: %lx\n", addr);

    // set up ftrace hook
    ops.func = hook_commit_creds;
    ops.flags = PHOTON_RING_FTRACE_FLAGS;

    // register ftrace hook
    ret = ftrace_set_filter_ip(&ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to set ftrace filter: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to register ftrace function: %d\n", ret);
        ftrace_set_filter_ip(&ops, addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully hooked commit_creds\n");
    printk(KERN_INFO "[PHOTON RING] now monitoring for privilege escalation...\n");

    return 0;
}

void become_root_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing become_root detector...\n");

    unregister_ftrace_function(&ops);
    ftrace_set_filter_ip(&ops, 0, 1, 0);

    printk(KERN_INFO "[PHOTON RING] become_root detector removed\n");
}
