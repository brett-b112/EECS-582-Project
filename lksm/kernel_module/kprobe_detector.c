#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jamie");
MODULE_DESCRIPTION("Kprobe registration using ftrace");
MODULE_VERSION("1.0");

static struct ftrace_ops ops;

static notrace void hook_kprobe_register(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct kprobe *kp;

    if (!regs)
        return;
    
    // get first arg (struct kprobe *p)
    // first arg is in rdi
    kp = (struct kprobe *)regs->di;

    if (kp) {
        // log kprobe registration event
        if (kp->symbol_name) {
            printk(KERN_ALERT "[PHOTON RING] Kprobe registered for symbol: %s\n", kp->symbol_name);

            // check for suspicious patterns
            if (strcmp(kp->symbol_name, "kallsyms_lookup_name") == 0) {
                printk(KERN_ALERT "[PHOTON RING] SUSPICIOUS *** kallsyms_lookup_name probe detected!\n");
            }
        }
    }
}

static int __init detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing kprobe detector...\n");

    // get the register_kprobe function address
    addr = (unsigned long)register_kprobe;

    printk(KERN_INFO "[PHOTON RING] found register_kprobe at: %lx\n", addr);

    // set up ftrace hook
    ops.func = hook_kprobe_register;
    ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    // register ftrace hook
    ret = ftrace_set_filter_ip(&ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to set ftrace filter: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to register ftrace function: %d\n", ret);
        ftrace_set_filter_ip(&ops, addr, 1, 0); // remove filter
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully hooked register_kprobe\n");
    printk(KERN_INFO "[PHOTON RING] now monitoring all kprobe registrations...\n");

    return 0;
}

static void __exit detector_exit(void) 
{
    printk(KERN_INFO "[PHOTON RING] removing kprobe detector...\n");

    // unregister ftrace hook
    unregister_ftrace_function(&ops);
    ftrace_set_filter_ip(&ops, 0, 1, 0);

    printk(KERN_INFO "[PHOTON RING] kprobe detector removed\n");
}

module_init(detector_init);
module_exit(detector_exit);