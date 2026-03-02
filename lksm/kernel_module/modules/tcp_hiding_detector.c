// tcp_hiding_detector.c
// Detects TCP/UDP connection hiding via ftrace hooks (targets Singularity-style rootkits)

// Singularity's hiding_tcp.c uses ftrace_set_filter_ip to hook:
//   tcp4_seq_show, tcp6_seq_show  -- hides entries from /proc/net/tcp[6]
//   udp4_seq_show, udp6_seq_show  -- hides entries from /proc/net/udp[6]
//   tpacket_rcv                   -- drops raw packets on AF_PACKET sockets

// This detector uses a kprobe on ftrace_set_filter_ip (rather than ftrace) and
// fires a SUSPICIOUS alert whenever a caller tries to install a hook on any of
// those functions.

// Why kprobes instead of ftrace?
// ftrace refuses to hook its own infrastructure (ftrace_set_filter_ip returns
// -EINVAL / -22 when you try). Kprobes inserts a breakpoint instruction directly
// into the function prologue and has no such restriction.
// See bpf_hook_detector.c for a detailed explanation of the same design decision.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/tcp_hiding_detector.h"

// Functions that Singularity hooks to hide TCP/UDP connections
static const char *tcp_hiding_names[] = {
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "tpacket_rcv",
};

#define NUM_TCP_TARGETS (sizeof(tcp_hiding_names) / sizeof(tcp_hiding_names[0]))

static unsigned long tcp_hiding_addrs[NUM_TCP_TARGETS];

/*
 * Self-detection avoidance: set to 1 while this module registers/unregisters
 * its own kprobe so the handler ignores those internal ftrace_set_filter_ip calls.
 */
static atomic_t self_hooking = ATOMIC_INIT(0);

static struct kprobe kp_tcp;

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

/*
 * Kprobe pre_handler — called every time ftrace_set_filter_ip is entered.
 *
 * ftrace_set_filter_ip(struct ftrace_ops *ops, unsigned long ip, int remove, int reset)
 *   arg 0 = ops
 *   arg 1 = ip   (the target address being hooked)
 *   arg 2 = remove flag
 */
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

    for (i = 0; i < NUM_TCP_TARGETS; i++) {
        if (tcp_hiding_addrs[i] && target_ip == tcp_hiding_addrs[i]) {
            printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** ftrace hook on %s detected!"
                   " Possible TCP hiding rootkit! (caller: %pS) by process '%s' (PID %d)\n",
                   tcp_hiding_names[i], (void *)PHOTON_RING_KPROBE_GET_ARG(regs, 0),
                   current->comm, current->pid);
            return 0;
        }
    }

    return 0;
}

int __init tcp_hiding_detector_init(void)
{
    int ret;
    int i;
    int resolved = 0;

    printk(KERN_INFO "[PHOTON RING] Initializing TCP hiding detector...\n");

    // Resolve addresses of the functions Singularity hooks
    for (i = 0; i < NUM_TCP_TARGETS; i++) {
        tcp_hiding_addrs[i] = lookup_name(tcp_hiding_names[i]);
        if (tcp_hiding_addrs[i]) {
            printk(KERN_INFO "[PHOTON RING] TCP target resolved: %s at %lx\n",
                   tcp_hiding_names[i], tcp_hiding_addrs[i]);
            resolved++;
        } else {
            printk(KERN_WARNING "[PHOTON RING] TCP target not found: %s\n",
                   tcp_hiding_names[i]);
        }
    }

    if (resolved == 0) {
        printk(KERN_ERR "[PHOTON RING] TCP hiding detector: no targets resolved, aborting\n");
        return -ENOENT;
    }

    // Use a kprobe on ftrace_set_filter_ip to catch rootkit hook installation
    kp_tcp.symbol_name = "ftrace_set_filter_ip";
    kp_tcp.pre_handler = handler_pre;

    atomic_set(&self_hooking, 1);
    ret = register_kprobe(&kp_tcp);
    atomic_set(&self_hooking, 0);

    if (ret) {
        printk(KERN_ERR "[PHOTON RING] TCP hiding detector: kprobe register failed: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] TCP hiding detector active (%d/%zu targets resolved)!\n",
           resolved, NUM_TCP_TARGETS);
    printk(KERN_INFO "[PHOTON RING] Monitoring ftrace_set_filter_ip for hooks on:\n");
    for (i = 0; i < NUM_TCP_TARGETS; i++) {
        if (tcp_hiding_addrs[i])
            printk(KERN_INFO "[PHOTON RING]   - %s\n", tcp_hiding_names[i]);
    }

    return 0;
}

void __exit tcp_hiding_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] Removing TCP hiding detector...\n");

    atomic_set(&self_hooking, 1);
    unregister_kprobe(&kp_tcp);
    atomic_set(&self_hooking, 0);

    printk(KERN_INFO "[PHOTON RING] TCP hiding detector removed\n");
}
