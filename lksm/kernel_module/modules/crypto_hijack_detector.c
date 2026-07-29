#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include "photon_ring_arch.h"
#include "event_manager.h"
#include "crypto_hijack_detector.h"

/*
 * Algorithm names Photon Ring itself relies on for event encryption.
 * A registration matching one of these after boot is either:
 *   - a legitimate late module load (rare, worth logging), or
 *   - a deliberate shadow/hijack attempt targeting our crypto path.
 * We can't distinguish the two from here, so we always alert and let
 * userspace correlate against expected boot-time module loads.
 */
static const char * const watched_crypto_names[] = {
    "gcm(aes)",
    "aes",
    "hmac(sha256)",
    "sha256",
    "ghash",
    NULL
};

static bool is_watched_crypto_name(const char *name)
{
    const char * const *entry;

    if (!name || !*name)
        return false;

    for (entry = watched_crypto_names; *entry; entry++) {
        if (strcmp(*entry, name) == 0)
            return true;
    }
    return false;
}

static struct ftrace_ops crypto_register_ops;

static notrace void hook_crypto_register_alg(unsigned long ip,
                                             unsigned long parent_ip,
                                             struct ftrace_ops *ops,
                                             struct ftrace_regs *fregs)
{
    struct crypto_alg *alg;
    struct crypto_hijack_data payload;

    alg = (struct crypto_alg *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!alg)
        return;

    if (!is_watched_crypto_name(alg->cra_name))
        return;

    printk(KERN_ALERT
           "[PHOTON RING] SUSPICIOUS crypto_register_alg(\"%s\", driver=\"%s\") "
           "— possible crypto shadowing/hijack, caller_ip=0x%lx comm=%s pid=%d\n",
           alg->cra_name, alg->cra_driver_name, parent_ip,
           current->comm, current->pid);

    memset(&payload, 0, sizeof(payload));
    strncpy(payload.cra_name, alg->cra_name, sizeof(payload.cra_name) - 1);
    strncpy(payload.cra_driver_name, alg->cra_driver_name,
            sizeof(payload.cra_driver_name) - 1);
    payload.cra_priority  = alg->cra_priority;
    payload.return_addr   = parent_ip;

    photon_log_event(PHOTON_EVENT_CRYPTO_HIJACK,
                     PHOTON_DETECTOR_CRYPTO,
                     PHOTON_SEV_CRITICAL,
                     &payload, sizeof(payload));
}

int crypto_hijack_detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing crypto_hijack detector...\n");

    addr = (unsigned long)crypto_register_alg;

    crypto_register_ops.func  = hook_crypto_register_alg;
    crypto_register_ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&crypto_register_ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] crypto_hijack: "
               "ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&crypto_register_ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] crypto_hijack: "
               "register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&crypto_register_ops, addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] crypto_hijack detector active — "
           "monitoring crypto_register_alg for hijack attempts\n");
    return 0;
}

void crypto_hijack_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing crypto_hijack detector...\n");
    unregister_ftrace_function(&crypto_register_ops);
    ftrace_set_filter_ip(&crypto_register_ops, 0, 1, 0);
    printk(KERN_INFO "[PHOTON RING] crypto_hijack detector removed\n");
}