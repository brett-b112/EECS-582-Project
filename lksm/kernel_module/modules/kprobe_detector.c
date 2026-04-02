#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include "photon_ring_arch.h"
#include "kprobe_detector.h"
#include "watchlists.h"
#include "event_manager.h"

static struct ftrace_ops ops;

/*
 * Cached address of kallsyms_lookup_name, resolved once during init via the
 * kprobe bootstrap technique.  Exposed via kprobe_detector_get_kallsyms_addr()
 * so that kallsyms_detector can hook the function without repeating the
 * bootstrap independently.  Written once before any other detector runs;
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
    struct probe_hook_data payload;
    u8 severity;

    /* ignore registrations originating from within this module */
    if (within_module(parent_ip, THIS_MODULE))
        return;

    kp = (struct kprobe *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!kp || !kp->symbol_name)
        return;

    memset(&payload, 0, sizeof(payload));
    strncpy(payload.symbol_name, kp->symbol_name,
            sizeof(payload.symbol_name) - 1);
    payload.target_addr  = (unsigned long)kp->addr;
    payload.handler_addr = 0;
    payload.entry_addr   = 0;
    payload.maxactive    = 0;
    payload.batch_count  = 1;

    if (photon_is_watchlisted(kp->symbol_name)) {
        payload.flags |= PROBE_FLAG_WATCHLISTED;
        severity = PHOTON_SEV_CRITICAL;
        printk(KERN_ALERT
               "[PHOTON RING] kprobe registered on watchlisted symbol: %s "
               "(addr=0x%lx)\n",
               kp->symbol_name, payload.target_addr);
    } else {
        severity = PHOTON_SEV_SUSPICIOUS;
        printk(KERN_WARNING
               "[PHOTON RING] kprobe registered: %s (addr=0x%lx)\n",
               kp->symbol_name, payload.target_addr);
    }

    photon_log_event(PHOTON_EVENT_PROBE_KPROBE,
                     PHOTON_DETECTOR_KPROBE,
                     severity,
                     &payload, sizeof(payload));
}

int kprobe_detector_init(void)
{
    struct kprobe bootstrap_kp = {
        .symbol_name = "kallsyms_lookup_name",
    };
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing kprobe detector...\n");

    /*
     * Resolve kallsyms_lookup_name via the kprobe bootstrap technique.
     * kallsyms_lookup_name is not exported on kernels >= 5.7; using kprobe
     * keeps the resolution path identical on all supported kernel versions.
     * The within_module() guard in hook_kprobe_register suppresses the event
     * that would otherwise fire here.
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

    addr = (unsigned long)register_kprobe;
    printk(KERN_INFO "[PHOTON RING] register_kprobe at: 0x%lx\n", addr);

    ops.func  = hook_kprobe_register;
    ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] ftrace_set_filter_ip failed: %d\n", ret);
        g_kallsyms_addr = 0;
        return ret;
    }

    ret = register_ftrace_function(&ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&ops, addr, 1, 0);
        g_kallsyms_addr = 0;
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] kprobe detector active — "
           "monitoring register_kprobe\n");
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