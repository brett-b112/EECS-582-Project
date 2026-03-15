// icmp_hook_detector.c
// Detects ICMP-based backdoors via ftrace hooks (targets Singularity-style rootkits)

// Singularity's icmp.c uses ftrace_set_filter_ip to hook:
//   icmp_rcv             -- intercepts ICMP echo requests looking for a magic
//                           sequence number (1337) and spawns a reverse shell
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/icmp_hook_detector.h"

// Functions that Singularity hooks to intercept ICMP packets
static const char *icmp_hook_names[] = {
    "icmp_rcv",
};

#define NUM_ICMP_TARGETS (sizeof(icmp_hook_names) / sizeof(icmp_hook_names[0]))

static unsigned long icmp_hook_addrs[NUM_ICMP_TARGETS];

//  Self-detection avoidance: set to 1 while this module registers/unregisters
//  its own kprobe so the handler ignores those internal ftrace_set_filter_ip calls.
static atomic_t self_hooking = ATOMIC_INIT(0);

static struct kprobe kp_icmp;

static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;

    if (register_kprobe(&kp) < 0)
        return 0;

    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

// Kprobe pre_handler — called every time ftrace_set_filter_ip is entered.
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long target_ip;
    unsigned long remove;
    int i;

    if (atomic_read(&self_hooking))
        return 0;

    target_ip = PHOTON_RING_KPROBE_GET_ARG(regs, 1);
    remove    = PHOTON_RING_KPROBE_GET_ARG(regs, 2);

    // Only flag new hook installations, not removals
    if (remove)
        return 0;

    for (i = 0; i < NUM_ICMP_TARGETS; i++) {
        if (icmp_hook_addrs[i] && target_ip == icmp_hook_addrs[i]) {
            printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** ftrace hook on %s detected!"
                   " Possible ICMP backdoor rootkit! (caller: %pS) by process '%s' (PID %d)\n",
                   icmp_hook_names[i], (void *)PHOTON_RING_KPROBE_GET_ARG(regs, 0),
                   current->comm, current->pid);
            return 0;
        }
    }

    return 0;
}

int __init icmp_hook_detector_init(void)
{
    int ret;
    int i;
    int resolved = 0;

    printk(KERN_INFO "[PHOTON RING] Initializing ICMP hook detector...\n");

    // Resolve addresses of the functions Singularity hooks
    for (i = 0; i < NUM_ICMP_TARGETS; i++) {
        icmp_hook_addrs[i] = lookup_name(icmp_hook_names[i]);
        if (icmp_hook_addrs[i]) {
            printk(KERN_INFO "[PHOTON RING] ICMP target resolved: %s at %lx\n",
                   icmp_hook_names[i], icmp_hook_addrs[i]);
            resolved++;
        } else {
            printk(KERN_WARNING "[PHOTON RING] ICMP target not found: %s\n",
                   icmp_hook_names[i]);
        }
    }

    if (resolved == 0) {
        printk(KERN_ERR "[PHOTON RING] ICMP hook detector: no targets resolved, aborting\n");
        return -ENOENT;
    }

    // Use a kprobe on ftrace_set_filter_ip to catch rootkit hook installation
    kp_icmp.symbol_name = "ftrace_set_filter_ip";
    kp_icmp.pre_handler = handler_pre;

    atomic_set(&self_hooking, 1);
    ret = register_kprobe(&kp_icmp);
    atomic_set(&self_hooking, 0);

    if (ret) {
        printk(KERN_ERR "[PHOTON RING] ICMP hook detector: kprobe register failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] ICMP hook detector active (%d/%zu targets resolved)!\n",
           resolved, NUM_ICMP_TARGETS);
    printk(KERN_INFO "[PHOTON RING] Monitoring ftrace_set_filter_ip for hooks on:\n");
    for (i = 0; i < NUM_ICMP_TARGETS; i++) {
        if (icmp_hook_addrs[i])
            printk(KERN_INFO "[PHOTON RING]   - %s\n", icmp_hook_names[i]);
    }

    return 0;
}

void __exit icmp_hook_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] Removing ICMP hook detector...\n");

    atomic_set(&self_hooking, 1);
    unregister_kprobe(&kp_icmp);
    atomic_set(&self_hooking, 0);

    printk(KERN_INFO "[PHOTON RING] ICMP hook detector removed\n");
}
