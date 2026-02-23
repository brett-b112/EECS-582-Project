// tcp_hiding_detector.c
// Detects TCP/UDP connection hiding via ftrace hooks (targets Singularity-style rootkits)
//
// Singularity's hiding_tcp.c uses ftrace_set_filter_ip to hook:
//   tcp4_seq_show, tcp6_seq_show  -- hides entries from /proc/net/tcp[6]
//   udp4_seq_show, udp6_seq_show  -- hides entries from /proc/net/udp[6]
//   tpacket_rcv                   -- drops raw packets on AF_PACKET sockets
//
// This detector hooks ftrace_set_filter_ip itself and fires a SUSPICIOUS alert
// whenever a caller tries to install a hook on any of those functions.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
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

#define NUM_TCP_TARGETS 5

static unsigned long tcp_hiding_addrs[NUM_TCP_TARGETS];

static struct ftrace_ops ops_ftrace_filter;

// ============================================================================
// Helper: use a temporary kprobe to resolve an unexported symbol address
// ============================================================================
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

// ============================================================================
// Hook on ftrace_set_filter_ip
//
// Signature: int ftrace_set_filter_ip(struct ftrace_ops *ops,
//                                     unsigned long ip,
//                                     int remove, int reset)
// args: 0=ops, 1=ip, 2=remove, 3=reset
// ============================================================================
static notrace void hook_ftrace_set_filter_ip(unsigned long ip,
                                               unsigned long parent_ip,
                                               struct ftrace_ops *ops,
                                               struct ftrace_regs *fregs)
{
    unsigned long target_ip;
    int remove;
    int i;

    target_ip = (unsigned long)PHOTON_RING_GET_ARG(fregs, 1);
    remove    = (int)(long)PHOTON_RING_GET_ARG(fregs, 2);

    // Only flag new hook installations, not removals
    if (remove)
        return;

    for (i = 0; i < NUM_TCP_TARGETS; i++) {
        if (tcp_hiding_addrs[i] && target_ip == tcp_hiding_addrs[i]) {
            printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** ftrace hook on %s detected!"
                   " Possible TCP hiding rootkit! (caller: %pS)\n",
                   tcp_hiding_names[i], (void *)parent_ip);
            return;
        }
    }
}

// ============================================================================
// Module initialization
// ============================================================================
int __init tcp_hiding_detector_init(void)
{
    unsigned long filter_ip_addr;
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

    // Hook ftrace_set_filter_ip to catch rootkit hook installation
    filter_ip_addr = (unsigned long)ftrace_set_filter_ip;

    ops_ftrace_filter.func  = hook_ftrace_set_filter_ip;
    ops_ftrace_filter.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops_ftrace_filter, filter_ip_addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] TCP hiding detector: ftrace filter set failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&ops_ftrace_filter);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] TCP hiding detector: ftrace register failed: %d\n", ret);
        ftrace_set_filter_ip(&ops_ftrace_filter, filter_ip_addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] TCP hiding detector active (%d/%d targets resolved)!\n",
           resolved, NUM_TCP_TARGETS);
    printk(KERN_INFO "[PHOTON RING] Monitoring ftrace_set_filter_ip for hooks on:\n");
    for (i = 0; i < NUM_TCP_TARGETS; i++) {
        if (tcp_hiding_addrs[i])
            printk(KERN_INFO "[PHOTON RING]   - %s\n", tcp_hiding_names[i]);
    }

    return 0;
}

// ============================================================================
// Module cleanup
// ============================================================================
void __exit tcp_hiding_detector_exit(void)
{
    unsigned long filter_ip_addr = (unsigned long)ftrace_set_filter_ip;

    printk(KERN_INFO "[PHOTON RING] Removing TCP hiding detector...\n");

    unregister_ftrace_function(&ops_ftrace_filter);
    ftrace_set_filter_ip(&ops_ftrace_filter, filter_ip_addr, 1, 0);

    printk(KERN_INFO "[PHOTON RING] TCP hiding detector removed\n");
}
