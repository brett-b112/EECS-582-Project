#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include "photon_ring_arch.h"
#include "kprobe_detector.h"
#include "watchlists.h"
#include "watchlist_resolver.h"
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
    struct kprobe        *kp;
    struct probe_hook_data payload;
    u8                    severity;
    const char           *effective_name = NULL;
    bool                  name_was_nulled = false;

    /* ignore registrations originating from within this module */
    if (within_module(parent_ip, THIS_MODULE))
        return;

    kp = (struct kprobe *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!kp)
        return;

    /*
     * Evasion detection: a rootkit that pre-resolves kprobe.addr and
     * deliberately zeros kprobe.symbol_name attempts to bypass detectors
     * (like this one) that only inspect symbol_name.  If symbol_name is
     * NULL but addr is set, reverse-look up the address in our pre-built
     * watchlist dictionary.
     *
     * The hook_register_kprobe pattern from kprobe-based rootkits does
     * exactly this for kprobes originating from within the rootkit module:
     * it strips symbol_name before forwarding to the real register_kprobe
     * so that any observer checking symbol_name sees nothing.
     *
     * If the address doesn't match anything in the watchlist the probe is
     * still reported — we just have no name to annotate it with.
     */
    if (!kp->symbol_name) {
        unsigned long probe_addr = (unsigned long)kp->addr;

        name_was_nulled = true;
        effective_name  = watchlist_resolver_lookup_name(probe_addr);

        if (effective_name) {
            /*
             * Address matched a watchlisted symbol — almost certainly
             * deliberate evasion.  Log loudly and treat as CRITICAL.
             */
            printk(KERN_ALERT
                   "[PHOTON RING] kprobe evasion detected: symbol_name is NULL "
                   "but addr=0x%lx resolves to watchlisted symbol \"%s\" — "
                   "caller_ip=0x%lx comm=%s pid=%d\n",
                   probe_addr, effective_name,
                   parent_ip, current->comm, current->pid);
        } else {
            /*
             * symbol_name is NULL and address is unknown.  Still suspicious
             * (legitimate callers set symbol_name) but we cannot name the
             * target.  Report with a placeholder so the event is not silently
             * dropped.
             */
            printk(KERN_WARNING
                   "[PHOTON RING] kprobe with NULL symbol_name: addr=0x%lx "
                   "— caller_ip=0x%lx comm=%s pid=%d\n",
                   probe_addr, parent_ip, current->comm, current->pid);
        }
    } else {
        effective_name = kp->symbol_name;
    }

    /*
     * Build the payload.  effective_name may be NULL here only in the
     * name_was_nulled + unrecognised-address branch; handle that safely.
     */
    memset(&payload, 0, sizeof(payload));

    if (effective_name) {
        strncpy(payload.symbol_name, effective_name,
                sizeof(payload.symbol_name) - 1);
    } else {
        /*
         * No symbol name available — embed the raw address so the event
         * record is still meaningful in Elasticsearch.
         */
        snprintf(payload.symbol_name, sizeof(payload.symbol_name),
                 "<unknown:0x%lx>", (unsigned long)kp->addr);
    }

    payload.target_addr  = (unsigned long)kp->addr;
    payload.handler_addr = 0;
    payload.entry_addr   = 0;
    payload.maxactive    = 0;
    payload.batch_count  = 1;

    /* Determine severity and watchlist flag. */
    if (name_was_nulled && effective_name) {
        /*
         * Confirmed evasion: nulled name, watchlisted address.
         * Highest severity; set both flags so consumers can distinguish
         * this sub-case from an ordinary watchlist hit.
         */
        payload.flags = PROBE_FLAG_WATCHLISTED;
        severity = PHOTON_SEV_CRITICAL;
    } else if (name_was_nulled) {
        /*
         * Nulled name, unknown address — suspicious but unconfirmed.
         * Mark evasion attempt; severity stays at SUSPICIOUS until we
         * know what is being hooked.
         */
        severity = PHOTON_SEV_SUSPICIOUS;
    } else if (effective_name && photon_is_watchlisted(effective_name)) {
        /* Normal registration targeting a watchlisted symbol. */
        payload.flags |= PROBE_FLAG_WATCHLISTED;
        severity = PHOTON_SEV_CRITICAL;
        printk(KERN_ALERT
               "[PHOTON RING] kprobe registered on watchlisted symbol: %s "
               "(addr=0x%lx)\n",
               effective_name, payload.target_addr);
    } else {
        /* Non-watchlisted, non-evasive registration — still log it. */
        severity = PHOTON_SEV_SUSPICIOUS;
        printk(KERN_WARNING
               "[PHOTON RING] kprobe registered: %s (addr=0x%lx)\n",
               effective_name ? effective_name : "<unknown>",
               payload.target_addr);
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

    /*
     * Build the watchlist address dictionary now that we have
     * kallsyms_lookup_name.  This is what lets us later detect the
     * symbol_name-nulling evasion technique in hook_kprobe_register.
     */
    watchlist_resolver_populate((kallsyms_lookup_name_fn)g_kallsyms_addr);

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