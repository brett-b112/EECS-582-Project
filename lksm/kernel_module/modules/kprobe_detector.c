#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include "../include/photon_ring_arch.h"
#include "../include/kprobe_detector.h"
#include "../include/event_manager.h"

static struct ftrace_ops ops;

/*
 * Cached address of kallsyms_lookup_name, resolved once during init via the
 * kprobe bootstrap technique (register a kprobe by symbol name, read .addr,
 * unregister).  Exposed to other detectors through
 * kprobe_detector_get_kallsyms_addr() so they can hook the function via
 * ftrace without repeating the bootstrap or touching unexported symbols.
 *
 * Written once in kprobe_detector_init before any other detector runs;
 * read-only thereafter — no locking needed.
 */
static unsigned long g_kallsyms_addr = 0;

unsigned long kprobe_detector_get_kallsyms_addr(void)
{
    return g_kallsyms_addr;
}

static notrace void hook_kprobe_register(unsigned long ip,
                                         unsigned long parent_ip,
                                         struct ftrace_ops *ops,
                                         struct ftrace_regs *fregs)
{
    struct kprobe *kp;
    struct kprobe_event_data event_data;

    /* get first arg (struct kprobe *p) portably via ftrace_regs */
    kp = (struct kprobe *)PHOTON_RING_GET_ARG(fregs, 0);

    if (kp) {
        if (kp->symbol_name) {
            printk(KERN_ALERT "[PHOTON RING] Kprobe registered for symbol: %s\n",
                   kp->symbol_name);

            memset(&event_data, 0, sizeof(event_data));
            strncpy(event_data.symbol_name, kp->symbol_name,
                    sizeof(event_data.symbol_name) - 1);
            event_data.addr  = (unsigned long)kp->addr;
            event_data.flags = 0;

            /* check for suspicious patterns */
            if (strcmp(kp->symbol_name, "kallsyms_lookup_name") == 0) {
                printk(KERN_ALERT
                       "[PHOTON RING] SUSPICIOUS *** kallsyms_lookup_name "
                       "probe detected!\n");
            }

            photon_log_event(PHOTON_EVENT_KPROBE_REG,
                             PHOTON_DETECTOR_KPROBE,
                             &event_data,
                             sizeof(event_data));
        }
    }
}

int kprobe_detector_init(void)
{
    /*
     * kprobe used solely as a symbol resolver — registered, address read,
     * then immediately unregistered.  It is never meant to fire.
     *
     * This is the same bootstrap technique Singularity uses, which is why
     * our own hook_kprobe_register fires during this init and logs a
     * "kallsyms_lookup_name probe detected" alert.  That is expected; the
     * within_module() filter in kallsyms_detector suppresses the equivalent
     * alert there.  Here we simply accept the self-generated event as a
     * harmless artifact of initialisation ordering.
     */
    struct kprobe bootstrap_kp = {
        .symbol_name = "kallsyms_lookup_name",
    };
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing kprobe detector...\n");

    /*
     * Resolve kallsyms_lookup_name.
     * On kernels < 5.7 it is exported and &kallsyms_lookup_name would
     * compile, but using the kprobe bootstrap unconditionally keeps the code
     * path identical on all supported kernel versions.
     */
    ret = register_kprobe(&bootstrap_kp);
    if (ret) {
        printk(KERN_ERR
               "[PHOTON RING] kprobe bootstrap failed "
               "(could not resolve kallsyms_lookup_name): %d\n", ret);
        return ret;
    }

    g_kallsyms_addr = (unsigned long)bootstrap_kp.addr;
    unregister_kprobe(&bootstrap_kp);

    printk(KERN_INFO "[PHOTON RING] resolved kallsyms_lookup_name at: 0x%lx\n",
           g_kallsyms_addr);

    /* now hook register_kprobe to monitor future kprobe registrations */
    addr = (unsigned long)register_kprobe;

    printk(KERN_INFO "[PHOTON RING] found register_kprobe at: 0x%lx\n", addr);

    ops.func  = hook_kprobe_register;
    ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to set ftrace filter: %d\n", ret);
        g_kallsyms_addr = 0;
        return ret;
    }

    ret = register_ftrace_function(&ops);
    if (ret) {
        printk(KERN_ERR
               "[PHOTON RING] failed to register ftrace function: %d\n", ret);
        ftrace_set_filter_ip(&ops, addr, 1, 0);
        g_kallsyms_addr = 0;
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully hooked register_kprobe\n");
    printk(KERN_INFO "[PHOTON RING] now monitoring all kprobe registrations...\n");

    return 0;
}

void kprobe_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing kprobe detector...\n");

    unregister_ftrace_function(&ops);
    ftrace_set_filter_ip(&ops, 0, 1, 0);

    g_kallsyms_addr = 0;

    printk(KERN_INFO "[PHOTON RING] kprobe detector removed\n");
}