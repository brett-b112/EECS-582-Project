// trace_pid_detector.c
// Detects rootkits that hook sched_process_fork to auto-hide child processes
// of already-hidden PIDs (e.g. Singularity's trace_pid_init)
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include "../include/photon_ring_arch.h"
#include "../include/trace_pid_detector.h"

static struct ftrace_ops ops;
static unsigned long target_addr;

/*
 * The Singularity rootkit hooks the sched_process_fork tracepoint via
 * register_trace_sched_process_fork(). We monitor for this by hooking
 * tracepoint_probe_register — any module registering a probe on a
 * scheduling tracepoint is suspicious.
 */
static notrace void hook_tracepoint_probe_register(unsigned long ip,
                                                    unsigned long parent_ip,
                                                    struct ftrace_ops *fops,
                                                    struct ftrace_regs *fregs)
{
    struct tracepoint *tp;
    void *probe_fn;

    tp = (struct tracepoint *)PHOTON_RING_GET_ARG(fregs, 0);
    probe_fn = (void *)PHOTON_RING_GET_ARG(fregs, 1);

    if (!tp || !tp->name)
        return;

    /* Flag registrations on scheduling/process tracepoints */
    if (strncmp(tp->name, "sched_process_fork", 18) == 0 ||
        strncmp(tp->name, "sched_process_exec", 18) == 0 ||
        strncmp(tp->name, "sched_process_exit", 18) == 0) {
        printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** tracepoint probe registered on '%s'"
               " by process '%s' (PID %d), probe function at %pS."
               " Possible PID-hiding rootkit (trace_pid)!\n",
               tp->name, current->comm, current->pid, probe_fn);
    } else {
        printk(KERN_INFO "[PHOTON RING] Tracepoint probe registered on '%s'"
               " by process '%s' (PID %d)\n",
               tp->name, current->comm, current->pid);
    }
}

int trace_pid_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing trace_pid detector...\n");

    target_addr = (unsigned long)tracepoint_probe_register;

    printk(KERN_INFO "[PHOTON RING] found tracepoint_probe_register at: %lx\n",
           target_addr);

    ops.func = hook_tracepoint_probe_register;
    ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops, target_addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] trace_pid: failed to set ftrace filter: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] trace_pid: failed to register ftrace function: %d\n", ret);
        ftrace_set_filter_ip(&ops, target_addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully hooked tracepoint_probe_register\n");
    printk(KERN_INFO "[PHOTON RING] now monitoring for PID-hiding tracepoint hooks...\n");

    return 0;
}

void trace_pid_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing trace_pid detector...\n");

    unregister_ftrace_function(&ops);
    ftrace_set_filter_ip(&ops, target_addr, 1, 0);

    printk(KERN_INFO "[PHOTON RING] trace_pid detector removed\n");
}
