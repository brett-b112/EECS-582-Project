// clear_taint_dmesg_detector.c
// Detects rootkits that hook read syscalls and do_syslog to filter
// kernel log output, hiding evidence of hooking, taint, and module presence
// (e.g. Singularity's clear_taint_dmesg_init)
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/clear_taint_dmesg_detector.h"

static struct kprobe kp;

/*
 * The Singularity rootkit hooks do_syslog (the kernel's internal syslog
 * handler) along with read/pread/readv syscalls to filter keywords like
 * "ftrace", "hook", "taint", "kallsyms_lookup_name" from kernel log
 * output before it reaches userspace.
 *
 * We use a kprobe on do_syslog since it is not exported to modules.
 *
 * do_syslog signature: int do_syslog(int type, char __user *buf, int len, int source)
 *   type 0: close log
 *   type 2: read from log
 *   type 3: read all messages remaining in ring buffer
 *   type 5: clear ring buffer
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int type;

    type = (int)PHOTON_RING_KPROBE_GET_ARG(regs, 0);

    /*
     * Type 5 = clear ring buffer -- rootkits use this to wipe evidence.
     * Flag this as highly suspicious.
     */
    if (type == 5) {
        printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** kernel ring buffer CLEAR (syslog type 5)"
               " by process '%s' (PID %d)."
               " Possible dmesg-clearing rootkit activity!\n",
               current->comm, current->pid);
        return 0;
    }

    /*
     * Types 2 and 3 are the read operations that rootkits hook to filter
     * output. Log these at info level for correlation in Kibana.
     */
    if (type == 2 || type == 3) {
        printk(KERN_INFO "[PHOTON RING] do_syslog read (type %d)"
               " by process '%s' (PID %d)\n",
               type, current->comm, current->pid);
    }

    return 0;
}

int clear_taint_dmesg_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing clear_taint_dmesg detector...\n");

    kp.symbol_name = "do_syslog";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] clear_taint_dmesg: failed to register kprobe: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully probed do_syslog at: %px\n", kp.addr);
    printk(KERN_INFO "[PHOTON RING] now monitoring for dmesg tampering behavior...\n");

    return 0;
}

void clear_taint_dmesg_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing clear_taint_dmesg detector...\n");

    unregister_kprobe(&kp);

    printk(KERN_INFO "[PHOTON RING] clear_taint_dmesg detector removed\n");
}
