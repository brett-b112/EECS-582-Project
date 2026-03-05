#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "include/kprobe_detector.h"
#include "include/taskstats_hook_detector.h"
#include "include/hooking_audit_detector.h"
#include "include/tcp_hiding_detector.h"
#include "include/become_root_detector.h"
#include "include/bpf_hook_detector.h"
#include "include/hook_file_access.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("582 group 32");
MODULE_DESCRIPTION("Photon Ring - Kernel rootkit detection system");
MODULE_VERSION("1.0");

/*
 * detector registry structure
 * add new detectors here to automatically include them in init/cleanup
 */
struct detector {
    const char *name;
    int (*init)(void);
    void (*exit)(void);
};

static struct detector detectors[] = {
    {
        .name = "kprobe_detector", 
        .init = kprobe_detector_init, 
        .exit = kprobe_detector_exit,
    },
    {
        .name = "taskstats_hook_detector",
        .init = taskstats_detector_init,
        .exit = taskstats_detector_exit,
    },
    {
        .name = "hooking_audit_detector",
        .init = audit_detector_init,
        .exit = audit_detector_exit,
    },
    {
        .name = "tcp_hiding_detector",
        .init = tcp_hiding_detector_init,
        .exit = tcp_hiding_detector_exit,
    },
    {
        .name = "become_root_detector",
        .init = become_root_detector_init,
        .exit = become_root_detector_exit,
    },
    {
        .name = "bpf_hook_detector",
        .init = bpf_hook_detector_init,
        .exit = bpf_hook_detector_exit,
    },
    {
    .name = "hook_file_access_detector",
    .init = file_access_detector_init,
    .exit = file_access_detector_exit,
    },
};

#define NUM_DETECTORS (sizeof(detectors) / sizeof(detectors[0]))

static int active_detectors = 0;

static int __init photon_ring_init(void)
{
    int ret;
    int i;

    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[PHOTON RING] Initializing detection system\n");
    printk(KERN_INFO "[PHOTON RING] Version: %s\n", THIS_MODULE->version);
    printk(KERN_INFO "========================================\n");

    // initialize all detectors
    for (i = 0; i < NUM_DETECTORS; i++) {
        printk(KERN_INFO "[PHOTON RING] Starting detector: %s\n", 
               detectors[i].name);
        
        ret = detectors[i].init();
        if (ret) {
            printk(KERN_ERR "[PHOTON RING] Failed to initialize %s: %d\n",
                   detectors[i].name, ret);
            
            // cleanup previously initialized detectors
            goto cleanup;
        }
        
        active_detectors++;
        printk(KERN_INFO "[PHOTON RING] %s initialized successfully\n",
               detectors[i].name);
    }

    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[PHOTON RING] All detectors active (%d/%zu)\n",
           active_detectors, NUM_DETECTORS);
    printk(KERN_INFO "[PHOTON RING] System is now monitoring...\n");
    printk(KERN_INFO "========================================\n");

    return 0;

cleanup:
    // cleanup in reverse order
    for (i = active_detectors - 1; i >= 0; i--) {
        printk(KERN_INFO "[PHOTON RING] Cleaning up %s\n", 
               detectors[i].name);
        detectors[i].exit();
    }
    
    printk(KERN_ERR "[PHOTON RING] Initialization failed\n");
    return ret;
}

static void __exit photon_ring_exit(void) 
{
    int i;

    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[PHOTON RING] Shutting down detection system\n");
    printk(KERN_INFO "========================================\n");

    // cleanup all detectors in reverse order
    for (i = active_detectors - 1; i >= 0; i--) {
        printk(KERN_INFO "[PHOTON RING] Stopping detector: %s\n",
               detectors[i].name);
        detectors[i].exit();
    }

    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[PHOTON RING] All detectors stopped\n");
    printk(KERN_INFO "[PHOTON RING] System shutdown complete\n");
    printk(KERN_INFO "========================================\n");
}

module_init(photon_ring_init);
module_exit(photon_ring_exit);