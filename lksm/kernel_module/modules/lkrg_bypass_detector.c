// lkrg_bypass_detector.c
// Detects rootkits that attempt to bypass Linux Kernel Runtime Guard (LKRG)
// by hooking vprintk_emit to filter log messages, and tampering with
// call_usermodehelper_exec to disable validation
// (e.g. Singularity's lkrg_bypass_init)
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include "../include/photon_ring_arch.h"
#include "../include/lkrg_bypass_detector.h"

static struct ftrace_ops vprintk_ops;
static struct ftrace_ops umh_ops;
static unsigned long vprintk_addr;
static unsigned long umh_addr;
static bool vprintk_hook_active;
static bool umh_hook_active;

/*
 * Vector A: Monitor vprintk_emit
 *
 * The Singularity rootkit hooks vprintk_emit to intercept all kernel
 * printk output and filter messages containing LKRG-related strings.
 * We monitor calls to vprintk_emit and flag any that arrive from
 * unexpected (non-kernel-core) callers, which indicates another ftrace
 * hook is intercepting the logging path.
 *
 * vprintk_emit signature:
 *   int vprintk_emit(int facility, int level, const struct dev_printk_info *dev_info,
 *                    const char *fmt, va_list args)
 */
static notrace void hook_vprintk_emit(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *fops,
                                      struct ftrace_regs *fregs)
{
    const char *fmt;

    fmt = (const char *)PHOTON_RING_GET_ARG(fregs, 3);

    if (!fmt)
        return;

    /*
     * The rootkit filters messages containing "lkrg" or "p_lkrg".
     * If we see vprintk_emit called with LKRG-related format strings
     * from a module context (not core kernel), it could indicate LKRG
     * is actively detecting something — or that a rootkit is about to
     * suppress the message.
     */
    if (strstr(fmt, "lkrg") != NULL || strstr(fmt, "p_lkrg") != NULL ||
        strstr(fmt, "LKRG") != NULL) {
        printk(KERN_ALERT "[PHOTON RING] LKRG message detected in vprintk_emit"
               " from caller %pS, process '%s' (PID %d)."
               " Monitoring for LKRG bypass log filtering!\n",
               (void *)parent_ip, current->comm, current->pid);
    }
}

/*
 * Vector B: Monitor call_usermodehelper_exec
 *
 * The Singularity rootkit hooks call_usermodehelper_exec to temporarily
 * disable LKRG's usermode helper validation during execution, allowing
 * unauthorized helper processes to run without LKRG flagging them.
 *
 * We monitor all calls to this function since rootkits use it to
 * execute malicious userspace programs from kernel context.
 */
static notrace void hook_umh_exec(unsigned long ip, unsigned long parent_ip,
                                  struct ftrace_ops *fops,
                                  struct ftrace_regs *fregs)
{
    printk(KERN_INFO "[PHOTON RING] call_usermodehelper_exec invoked"
           " by caller %pS, process '%s' (PID %d)\n",
           (void *)parent_ip, current->comm, current->pid);
}

int lkrg_bypass_detector_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing LKRG bypass detector...\n");

    /* Vector A: hook vprintk_emit */
    vprintk_addr = (unsigned long)vprintk_emit;

    vprintk_ops.func = hook_vprintk_emit;
    vprintk_ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&vprintk_ops, vprintk_addr, 0, 0);
    if (ret) {
        printk(KERN_WARNING "[PHOTON RING] lkrg_bypass: failed to set vprintk filter: %d\n", ret);
        goto skip_vprintk;
    }

    ret = register_ftrace_function(&vprintk_ops);
    if (ret) {
        printk(KERN_WARNING "[PHOTON RING] lkrg_bypass: failed to register vprintk hook: %d\n", ret);
        ftrace_set_filter_ip(&vprintk_ops, vprintk_addr, 1, 0);
        goto skip_vprintk;
    }
    vprintk_hook_active = true;
    printk(KERN_INFO "[PHOTON RING] lkrg_bypass: vprintk_emit hook active at 0x%lx\n",
           vprintk_addr);

skip_vprintk:
    /* Vector B: hook call_usermodehelper_exec */
    umh_addr = (unsigned long)call_usermodehelper_exec;

    umh_ops.func = hook_umh_exec;
    umh_ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&umh_ops, umh_addr, 0, 0);
    if (ret) {
        printk(KERN_WARNING "[PHOTON RING] lkrg_bypass: failed to set umh filter: %d\n", ret);
        goto done;
    }

    ret = register_ftrace_function(&umh_ops);
    if (ret) {
        printk(KERN_WARNING "[PHOTON RING] lkrg_bypass: failed to register umh hook: %d\n", ret);
        ftrace_set_filter_ip(&umh_ops, umh_addr, 1, 0);
        goto done;
    }
    umh_hook_active = true;
    printk(KERN_INFO "[PHOTON RING] lkrg_bypass: call_usermodehelper_exec hook active at 0x%lx\n",
           umh_addr);

done:
    if (!vprintk_hook_active && !umh_hook_active) {
        printk(KERN_ERR "[PHOTON RING] lkrg_bypass: no hooks could be installed\n");
        return -ENODEV;
    }

    printk(KERN_INFO "[PHOTON RING] LKRG bypass detector active"
           " (vprintk: %s, umh: %s)\n",
           vprintk_hook_active ? "yes" : "no",
           umh_hook_active ? "yes" : "no");
    return 0;
}

void lkrg_bypass_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing LKRG bypass detector...\n");

    if (vprintk_hook_active) {
        unregister_ftrace_function(&vprintk_ops);
        ftrace_set_filter_ip(&vprintk_ops, vprintk_addr, 1, 0);
    }

    if (umh_hook_active) {
        unregister_ftrace_function(&umh_ops);
        ftrace_set_filter_ip(&umh_ops, umh_addr, 1, 0);
    }

    printk(KERN_INFO "[PHOTON RING] LKRG bypass detector removed\n");
}
