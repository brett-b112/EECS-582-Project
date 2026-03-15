/*
 * bpf_hook_detector.c - Detects ftrace hooks targeting BPF-critical kernel functions
 *
 * Unlike other Photon Ring detectors (kprobe_detector, become_root_detector, etc.)
 * which use ftrace to hook their targets, this detector uses kprobes instead.
 *
 * Why kprobes instead of ftrace?
 * Our target function is ftrace_set_filter_ip — part of ftrace's own infrastructure.
 * Ftrace refuses to hook itself (returns -EINVAL / -22) because doing so would
 * create recursion: ftrace_set_filter_ip would need to call itself to set up
 * the filter, which is a circular dependency. Kprobes is a separate instrumentation
 * mechanism that inserts breakpoint instructions (BRK on ARM64, INT3 on x86)
 * directly into the function prologue, so it has no issue probing ftrace internals.
 *
 * Key differences from ftrace-based detectors:
 * - Uses struct kprobe + register_kprobe() instead of struct ftrace_ops +
 *   ftrace_set_filter_ip() + register_ftrace_function()
 * - Handler signature is kprobe's pre_handler(struct kprobe *, struct pt_regs *)
 *   instead of ftrace's callback(ip, parent_ip, ftrace_ops *, ftrace_regs *)
 * - Reads function arguments via PHOTON_RING_KPROBE_GET_ARG(regs, N) which works
 *   on pt_regs, instead of PHOTON_RING_GET_ARG(fregs, N) which works on ftrace_regs
 * - Both macros live in photon_ring_arch.h and are portable across architectures
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/bpf_hook_detector.h"
#include "../include/event_manager.h"

/* BPF-critical functions that the Singularity rootkit hooks via ftrace */
static const char *bpf_watchlist[] = {
    "bpf_iter_run_prog",
    "bpf_ringbuf_output",
    "__x64_sys_bpf",
    "bpf_check",
    "bpf_prog_load",
    "security_bpf",
    "security_bpf_map",
    "security_bpf_prog",
    "bpf_map_get_info_by_fd",
    "bpf_prog_get_info_by_fd",
    "bpf_trampoline_link_prog",
    "bpf_tracing_prog_attach",
    "perf_event_attach_bpf_prog",
};

#define BPF_WATCHLIST_SIZE (sizeof(bpf_watchlist) / sizeof(bpf_watchlist[0]))

/*
 * Self-detection avoidance: set to 1 during our own module's init/exit
 * so the kprobe handler skips ftrace_set_filter_ip calls from other
 * Photon Ring detectors initializing before us.
 */
static atomic_t self_hooking = ATOMIC_INIT(0);

/*
 * kprobe struct — unlike ftrace_ops, kprobe targets a single function by name.
 * The kernel resolves the symbol_name to an address and patches a breakpoint there.
 */
static struct kprobe kp;

/*
 * Kprobe pre_handler — called every time ftrace_set_filter_ip is entered.
 *
 * Compare with ftrace-based detectors which use:
 *   static notrace void callback(unsigned long ip, unsigned long parent_ip,
 *                                struct ftrace_ops *ops, struct ftrace_regs *fregs)
 *
 * Kprobe handlers receive struct pt_regs (CPU register snapshot) instead of
 * ftrace_regs, so we use PHOTON_RING_KPROBE_GET_ARG() instead of PHOTON_RING_GET_ARG().
 * Both macros are defined in photon_ring_arch.h as the architecture translation layer.
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long target_ip;
    unsigned long remove;
    char buf[KSYM_SYMBOL_LEN];
    int i;
    struct bpf_event_data event_data;

    /* skip calls made while we're setting up/tearing down */
    if (atomic_read(&self_hooking))
        return 0;

    /*
     * ftrace_set_filter_ip(struct ftrace_ops *ops, unsigned long ip,
     *                      int remove, int reset)
     * arg 1 = ip (the target address being filtered)
     * arg 2 = remove flag
     */
    target_ip = PHOTON_RING_KPROBE_GET_ARG(regs, 1);
    remove = PHOTON_RING_KPROBE_GET_ARG(regs, 2);

    /* only detect additions, not removals */
    if (remove)
        return 0;

    /* resolve target address to symbol name */
    sprint_symbol_no_offset(buf, target_ip);

    /* check against BPF watchlist */
    for (i = 0; i < BPF_WATCHLIST_SIZE; i++) {
        if (strcmp(buf, bpf_watchlist[i]) == 0) {
            printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** ftrace hook on BPF function: %s (addr %lx) by process '%s' (PID %d)\n",
                   buf, target_ip, current->comm, current->pid);

            // prepare event data
            memset(&event_data, 0, sizeof(event_data));
            strncpy(event_data.bpf_function, buf, sizeof(event_data.bpf_function));
            event_data.addr = target_ip;
            strncpy(event_data.process, current->comm, sizeof(event_data.process));
            event_data.pid = current->pid;

            // log event to secure channel
            photon_log_event(PHOTON_EVENT_BPF_REG,
            PHOTON_DETECTOR_SYSCALL,
            &event_data,
            sizeof(event_data));

            return 0;
        }
    }

    printk(KERN_INFO "[PHOTON RING] ftrace filter registered for: %s (addr %lx) by process '%s' (PID %d)\n",
           buf, target_ip, current->comm, current->pid);
    
    // prepare event data
    memset(&event_data, 0, sizeof(event_data));
    strncpy(event_data.bpf_function, buf, sizeof(event_data.bpf_function));
    event_data.addr = target_ip;
    strncpy(event_data.process, current->comm, sizeof(event_data.process));
    event_data.pid = current->pid;

    // log event to secure channel
    photon_log_event(PHOTON_EVENT_BPF_REG,
    PHOTON_DETECTOR_SYSCALL,
    &event_data,
    sizeof(event_data));
    
    return 0;
}

int bpf_hook_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing BPF hook detector...\n");

    /*
     * With kprobes we just specify the symbol name and a handler function.
     * Contrast with ftrace-based detectors which require:
     *   1. ops.func = callback;
     *   2. ops.flags = PHOTON_RING_FTRACE_FLAGS;
     *   3. ftrace_set_filter_ip(&ops, addr, 0, 0);
     *   4. register_ftrace_function(&ops);
     */
    kp.symbol_name = "ftrace_set_filter_ip";
    kp.pre_handler = handler_pre;

    /*
     * Set self_hooking so our handler ignores the ftrace_set_filter_ip
     * calls that register_kprobe itself makes internally.
     */
    atomic_set(&self_hooking, 1);

    ret = register_kprobe(&kp);
    if (ret) {
        atomic_set(&self_hooking, 0);
        printk(KERN_ERR "[PHOTON RING] failed to register kprobe for BPF detector: %d\n", ret);
        return ret;
    }

    atomic_set(&self_hooking, 0);

    printk(KERN_INFO "[PHOTON RING] successfully probed ftrace_set_filter_ip at: %px\n",
           kp.addr);
    printk(KERN_INFO "[PHOTON RING] now monitoring BPF function hooking (%zu targets)...\n",
           BPF_WATCHLIST_SIZE);

    return 0;
}

void bpf_hook_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing BPF hook detector...\n");

    atomic_set(&self_hooking, 1);
    unregister_kprobe(&kp);
    atomic_set(&self_hooking, 0);

    printk(KERN_INFO "[PHOTON RING] BPF hook detector removed\n");
}