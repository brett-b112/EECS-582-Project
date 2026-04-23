// photon_ring_audit_detector.c
// Detects audit subsystem manipulation and evasion
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/audit.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <net/sock.h>
#include "../include/photon_ring_arch.h"
#include "../include/hooking_audit_detector.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Max");
MODULE_DESCRIPTION("Detect audit subsystem manipulation and evasion");
MODULE_VERSION("1.0");


static atomic_t audit_unicast_calls  = ATOMIC_INIT(0);
static atomic_t audit_log_calls      = ATOMIC_INIT(0);
static unsigned long last_stats_print = 0;

#define STATS_INTERVAL_HZ  (30 * HZ)

static void print_statistics(void)
{
    unsigned long now = jiffies;

    if (time_before(now, last_stats_print + STATS_INTERVAL_HZ))
        return;

    last_stats_print = now;

    printk(KERN_INFO "[PHOTON RING][AUDIT] stats: "
           "netlink_unicast=%d  audit_log_start/end=%d\n",
           atomic_read(&audit_unicast_calls),
           atomic_read(&audit_log_calls));
}


static struct ftrace_ops ops_netlink_unicast;

static notrace void hook_netlink_unicast_detector(unsigned long ip,
                                                   unsigned long parent_ip,
                                                   struct ftrace_ops *ops,
                                                   struct ftrace_regs *fregs)
{
    struct sock    *ssk;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    ssk = (struct sock *)PHOTON_RING_GET_ARG(fregs, 0);
    skb = (struct sk_buff *)PHOTON_RING_GET_ARG(fregs, 1);

    if (!ssk || !skb)
        return;

    if (ssk->sk_protocol != NETLINK_AUDIT)
        return;

    atomic_inc(&audit_unicast_calls);

    if (skb->len >= NLMSG_HDRLEN) {
        nlh = (struct nlmsghdr *)skb->data;

        if (nlh->nlmsg_type >= AUDIT_FIRST_USER_MSG &&
            nlh->nlmsg_type <= AUDIT_LAST_USER_MSG) {
            printk(KERN_ALERT
                   "[PHOTON RING][AUDIT] SUSPICIOUS *** "
                   "NETLINK_AUDIT user message type=%u "
                   "caller=%pS pid=%d (%s) — "
                   "possible audit message suppression!\n",
                   nlh->nlmsg_type,
                   (void *)parent_ip,
                   current->pid, current->comm);
        }
    }

    print_statistics();
}


static struct ftrace_ops ops_audit_log_start;

static notrace void hook_audit_log_start_detector(unsigned long ip,
                                                   unsigned long parent_ip,
                                                   struct ftrace_ops *ops,
                                                   struct ftrace_regs *fregs)
{
    int type;

    type = (int)PHOTON_RING_GET_ARG(fregs, 2);

    atomic_inc(&audit_log_calls);

    {
        char sym[KSYM_NAME_LEN] = "<unknown>";
        unsigned long offset = 0, size = 0;

        kallsyms_lookup(parent_ip, &size, &offset, NULL, sym);

        if (strncmp(sym, "<unknown>", 9) == 0) {
            printk(KERN_ALERT
                   "[PHOTON RING][AUDIT] SUSPICIOUS *** "
                   "audit_log_start(type=%d) from unresolvable caller 0x%lx "
                   "pid=%d (%s) — possible log-creation hook!\n",
                   type, parent_ip,
                   current->pid, current->comm);
        }
    }
}


static struct ftrace_ops ops_audit_log_end;

static notrace void hook_audit_log_end_detector(unsigned long ip,
                                                 unsigned long parent_ip,
                                                 struct ftrace_ops *ops,
                                                 struct ftrace_regs *fregs)
{
    void *ab;

    ab = (void *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!ab)
        return;

    atomic_inc(&audit_log_calls);

    printk(KERN_DEBUG
           "[PHOTON RING][AUDIT] audit_log_end caller=%pS pid=%d (%s)\n",
           (void *)parent_ip,
           current->pid, current->comm);
}

static struct ftrace_ops ops_audit_syscall_entry;

static notrace void hook_audit_syscall_entry_detector(unsigned long ip,
                                                       unsigned long parent_ip,
                                                       struct ftrace_ops *ops,
                                                       struct ftrace_regs *fregs)
{
    int major;

    major = (int)PHOTON_RING_GET_ARG(fregs, 0);

#define NR_EXECVE       59
#define NR_FORK         57
#define NR_CLONE        56
#define NR_MMAP         9
#define NR_INIT_MODULE  175
#define NR_FINIT_MODULE 313

    switch (major) {
    case NR_EXECVE:
    case NR_FORK:
    case NR_CLONE:
    case NR_INIT_MODULE:
    case NR_FINIT_MODULE:
        printk(KERN_INFO
               "[PHOTON RING][AUDIT] syscall_entry syscall=%d "
               "caller=%pS pid=%d (%s)\n",
               major, (void *)parent_ip,
               current->pid, current->comm);
        break;
    case NR_MMAP:
        break;
    default:
        break;
    }
}


static unsigned long resolve_symbol(const char *name)
{
    struct kprobe kp;
    unsigned long addr;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = name;
    if (register_kprobe(&kp) < 0)
        return 0;

    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static int setup_ftrace_hook(struct ftrace_ops *ops,
                             ftrace_func_t func,
                             const char *symbol_name)
{
    unsigned long addr;
    int ret;

    addr = resolve_symbol(symbol_name);
    if (!addr) {
        printk(KERN_WARNING "[PHOTON RING][AUDIT] symbol \"%s\" not found — hook skipped\n",
               symbol_name);
        return -ENOENT;
    }

    memset(ops, 0, sizeof(*ops));
    ops->func  = func;
    ops->flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(ops, addr, 0 /* add */, 0 /* no reset */);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING][AUDIT] ftrace_set_filter_ip failed for \"%s\": %d\n",
               symbol_name, ret);
        return ret;
    }

    ret = register_ftrace_function(ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING][AUDIT] register_ftrace_function failed for \"%s\": %d\n",
               symbol_name, ret);
        ftrace_set_filter_ip(ops, addr, 1 /* remove */, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING][AUDIT] hook installed on \"%s\" @ 0x%lx\n",
           symbol_name, addr);
    return 0;
}


static void teardown_ftrace_hook(struct ftrace_ops *ops, const char *symbol_name)
{
    unsigned long addr;

    if (!ops->func)
        return;

    unregister_ftrace_function(ops);

    addr = resolve_symbol(symbol_name);
    if (addr)
        ftrace_set_filter_ip(ops, addr, 1 /* remove */, 0);

    ops->func = NULL;
}


int __init audit_detector_init(void)
{
    int ret;
    int hooks_installed = 0;

    printk(KERN_INFO "[PHOTON RING][AUDIT] Initializing audit evasion detector...\n");

    last_stats_print = jiffies;

    // Hook 1: netlink_unicast (primary audit evasion detection)
    ret = setup_ftrace_hook(&ops_netlink_unicast,
                            hook_netlink_unicast_detector,
                            "netlink_unicast");
    if (ret == 0)
        hooks_installed++;

    // Hook 2: audit_log_start
    ret = setup_ftrace_hook(&ops_audit_log_start,
                            hook_audit_log_start_detector,
                            "audit_log_start");
    if (ret == 0)
        hooks_installed++;

    // Hook 3: audit_log_end
    ret = setup_ftrace_hook(&ops_audit_log_end,
                            hook_audit_log_end_detector,
                            "audit_log_end");
    if (ret == 0)
        hooks_installed++;

    // Hook 4: __audit_syscall_entry
    ret = setup_ftrace_hook(&ops_audit_syscall_entry,
                            hook_audit_syscall_entry_detector,
                            "__audit_syscall_entry");
    if (ret == 0)
        hooks_installed++;

    if (hooks_installed == 0) {
        printk(KERN_ERR "[PHOTON RING][AUDIT] Failed to install any hooks!\n");
        return -ENOENT;
    }

    printk(KERN_INFO "[PHOTON RING][AUDIT] Audit detector active (%d hooks installed).\n",
           hooks_installed);
    printk(KERN_INFO "[PHOTON RING][AUDIT] Monitoring for:\n");
    printk(KERN_INFO "[PHOTON RING][AUDIT]   - Audit message interception (netlink_unicast)\n");
    printk(KERN_INFO "[PHOTON RING][AUDIT]   - Audit log creation suppression (audit_log_start)\n");
    printk(KERN_INFO "[PHOTON RING][AUDIT]   - Audit log finalization tampering (audit_log_end)\n");
    printk(KERN_INFO "[PHOTON RING][AUDIT]   - Syscall audit entry evasion (__audit_syscall_entry)\n");

    return 0;
}

void __exit audit_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING][AUDIT] Removing audit evasion detector...\n");

    teardown_ftrace_hook(&ops_audit_syscall_entry, "__audit_syscall_entry");
    teardown_ftrace_hook(&ops_audit_log_end,       "audit_log_end");
    teardown_ftrace_hook(&ops_audit_log_start,     "audit_log_start");
    teardown_ftrace_hook(&ops_netlink_unicast,      "netlink_unicast");

    synchronize_rcu();

    printk(KERN_INFO "[PHOTON RING][AUDIT] final stats: "
           "netlink_unicast=%d  audit_log_start/end=%d\n",
           atomic_read(&audit_unicast_calls),
           atomic_read(&audit_log_calls));

    printk(KERN_INFO "[PHOTON RING][AUDIT] Audit evasion detector removed.\n");
}

module_init(audit_detector_init);
module_exit(audit_detector_exit);