#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include "../include/photon_ring_arch.h"
#include "../include/event_manager.h"
#include "../include/become_root_detector.h"

#define PRIVESC_STACK_DEPTH     16

/*
 * Size of the buffer used to render the stack trace as a string for
 * substring matching. Each frame is roughly "  symbol+0xOFF/0xSIZ\n"
 * which is at most ~80 chars. 16 frames * 80 = 1280; 2048 is comfortable.
 */
#define PRIVESC_TRACE_BUF_SIZE  2048

/*
 * Legitimate callers confirmed present in /proc/kallsyms on this kernel.
 * stack_trace_snprint() renders symbol names exactly as kallsyms knows them,
 * so these substrings will appear verbatim in the rendered trace when the
 * credential change comes through a normal auth path.
 *
 * We use substring matching (strstr) rather than exact matching because
 * stack_trace_snprint() renders each frame as "  symbol+0xOFFSET/0xSIZE\n"
 * — the symbol name is a prefix of each line.
 */
static const char * const legitimate_callers[] = {
    "security_bprm_committed_creds",
    "cap_bprm_set_creds",
    "__sys_setuid",
    "__sys_setuid16",
    "__sys_setreuid",
    "__sys_setreuid16",
    "__sys_setresuid",
    "__sys_setresuid16",
    "__sys_setgid",
    "__sys_setgid16",
    "__sys_setregid",
    "__sys_setregid16",
    "__sys_setresgid",
    "__sys_setresgid16",
    "__sys_setfsuid",
    "__sys_setfsuid16",
    "__sys_setfsgid",
    "__sys_setfsgid16",
    "__sys_setns",
};

static struct ftrace_ops commit_creds_ops;

/*
 * stack_has_legitimate_caller - render stack to string, parse line by line,
 * and match only the bare symbol name (the portion before '+').
 *
 * stack_trace_snprint() renders each frame as:
 *   "symbol+0xOFFSET/0xSIZE [module]\n"
 *
 * We extract only the token before '+' on each line and compare it exactly
 * against the allowlist. This closes the strstr() prefix-bypass where a
 * rootkit could name its function "__x64_sys_setuid_evil" and fool a naive
 * substring match.
 *
 * Example line:  "commit_creds+0x18/0x40\n"
 * Extracted sym: "commit_creds"
 */

static bool stack_has_legitimate_caller(unsigned long *entries, unsigned int nr)
{
    char buf[PRIVESC_TRACE_BUF_SIZE];
    char *line_start, *line_end, *sym_start, *plus;
    char sym[KSYM_NAME_LEN];
    size_t sym_len;
    unsigned int i;

    memset(buf, 0, sizeof(buf));
    stack_trace_snprint(buf, sizeof(buf), entries, nr, 0);

    printk(KERN_INFO "[PHOTON RING] commit_creds stack trace:\n%s\n", buf);

    line_start = buf;

    while (*line_start) {
        line_end = strchr(line_start, '\n');
        if (!line_end)
            line_end = line_start + strlen(line_start);

        /*
         * Skip leading whitespace before the symbol name.
         * stack_trace_snprint() indents each frame with a space, so without
         * this we extract ' __sys_setuid' instead of '__sys_setuid' and the
         * strcmp against the allowlist never matches.
         */
        sym_start = line_start;
        while (sym_start < line_end && (*sym_start == ' ' || *sym_start == '\t'))
            sym_start++;

        /* find '+' within this line only */
        plus = NULL;
        {
            char *p;
            for (p = sym_start; p < line_end; p++) {
                if (*p == '+') {
                    plus = p;
                    break;
                }
            }
        }

        if (plus && plus > sym_start) {
            sym_len = plus - sym_start;

            if (sym_len < sizeof(sym)) {
                memcpy(sym, sym_start, sym_len);
                sym[sym_len] = '\0';

                printk(KERN_INFO "[PHOTON RING]   extracted sym: '%s'\n", sym);

                for (i = 0; i < ARRAY_SIZE(legitimate_callers); i++) {
                    if (strcmp(sym, legitimate_callers[i]) == 0)
                        return true;
                }
            }
        }

        if (*line_end == '\0')
            break;
        line_start = line_end + 1;
    }

    return false;
}

/*
 * hook_commit_creds - ftrace pre-call hook on commit_creds().
 *
 * Fires before commit_creds() executes so we can read both:
 *   - new_cred: the incoming struct cred * (arg0, via PHOTON_RING_GET_ARG)
 *   - old_cred: current->cred (always valid before the swap)
 *
 * Alert conditions (all must be true):
 *   1. old uid != 0  (process was not already root)
 *   2. new uid == 0  (transition is escalating to root)
 *   3. stack trace does not contain any legitimate_callers[] entry
 */
static notrace void hook_commit_creds(unsigned long ip, unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct ftrace_regs *fregs)
{
    struct cred *new_cred;
    const struct cred *old_cred;
    unsigned long stack_entries[PRIVESC_STACK_DEPTH];
    unsigned int nr_entries;
    struct becomeroot_event_data event_data;

    new_cred = (struct cred *)PHOTON_RING_GET_ARG(fregs, 0);
    if (!new_cred)
        return;

    old_cred = current->cred;
    if (!old_cred)
        return;

    /* fast path: not a root escalation — covers the vast majority of calls */
    if (old_cred->uid.val == 0 || new_cred->uid.val != 0)
        return;

    /*
     * Nonzero -> zero uid transition detected. Capture the stack.
     * Skip 1 frame to drop the ftrace trampoline from the trace.
     * stack_trace_save() is confirmed exported on this kernel.
     */
    nr_entries = stack_trace_save(stack_entries, PRIVESC_STACK_DEPTH, 1);

    if (stack_has_legitimate_caller(stack_entries, nr_entries))
        return;

    /*
     * No legitimate caller found — this is suspicious.
     */
    printk(KERN_ALERT
           "[PHOTON RING] SUSPICIOUS *** commit_creds uid escalation to root!\n");
    printk(KERN_ALERT
           "[PHOTON RING]   process: %s  pid: %d  uid: %u -> 0\n",
           current->comm, current->pid, old_cred->uid.val);

    memset(&event_data, 0, sizeof(event_data));
    strncpy(event_data.process, current->comm, sizeof(event_data.process) - 1);
    event_data.pid = current->pid;

    photon_log_event(PHOTON_EVENT_PRIVESC,
                     PHOTON_DETECTOR_KPROBE,
                     &event_data,
                     sizeof(event_data));
}

int become_root_detector_init(void)
{
    unsigned long addr;
    int ret;

    printk(KERN_INFO "[PHOTON RING] initializing become_root detector...\n");

    /* commit_creds is exported — take address directly, no lookup needed */
    addr = (unsigned long)commit_creds;
    printk(KERN_INFO "[PHOTON RING] commit_creds at: %lx\n", addr);

    commit_creds_ops.func  = hook_commit_creds;
    commit_creds_ops.flags = PHOTON_RING_FTRACE_FLAGS;

    ret = ftrace_set_filter_ip(&commit_creds_ops, addr, 0, 0);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to set ftrace filter: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&commit_creds_ops);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] failed to register ftrace function: %d\n", ret);
        ftrace_set_filter_ip(&commit_creds_ops, addr, 1, 0);
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] successfully hooked commit_creds\n");
    printk(KERN_INFO "[PHOTON RING] monitoring for suspicious uid escalations...\n");
    return 0;
}

void become_root_detector_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] removing become_root detector...\n");
    unregister_ftrace_function(&commit_creds_ops);
    ftrace_set_filter_ip(&commit_creds_ops, 0, 1, 0);
    printk(KERN_INFO "[PHOTON RING] become_root detector removed\n");
}