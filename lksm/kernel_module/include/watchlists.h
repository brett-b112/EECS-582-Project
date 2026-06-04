#ifndef PHOTON_RING_WATCHLISTS_H
#define PHOTON_RING_WATCHLISTS_H

/*
 * watchlists.h — Photon Ring
 *
 * Single source of truth for all watched kernel symbols.
 *
 */

#include <linux/string.h>

static const char * const photon_watchlist[] = {

    /* --- Unambiguously hostile -------------------------------------------
     * No legitimate out-of-tree module resolves or hooks these at runtime.
     * --------------------------------------------------------------------- */
    "tainted_mask",        /* reset_tainted — erase forensic trail  */
    "sys_call_table",      /* syscall table hijack                  */
    "ia32_sys_call_table", /* 32-bit compat syscall table hijack    */
    "_stext",              /* raw kernel text base — KASLR defeat   */
    "entry_SYSCALL_64",    /* syscall entry point patching          */

    /* filesystem / directory hiding */
    "filldir64",
    "filldir",
    "iterate_dir",

    /* network hiding */
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "tpacket_rcv",
    "icmp_rcv",

    /* privilege escalation */
    "commit_creds",
    "prepare_kernel_cred",
    "cap_capable",

    /* process / module hiding */
    "proc_pid_readdir",
    "proc_pid_lookup",

    /* signal interception (C2 channel) */
    "sys_kill",
    "do_send_sig_info",

    "module_alloc",           /* custom code injection           */
    "set_memory_x",           /* marking memory executable       */
    "ftrace_ops_list",        /* enumerating active ftrace hooks */
    "kthread_create_on_node", /* covert thread creation          */
    "find_module",            /* module list walking             */

    /* stat syscall hiding (hiding_stat pattern) */
    "__x64_sys_statx",
    "__x64_sys_stat",
    "__x64_sys_lstat",
    "__x64_sys_newstat",
    "__x64_sys_newlstat",
    "__x64_sys_getpriority",
    "__x64_sys_newfstatat",
    "__ia32_sys_statx",
    "__ia32_sys_stat",
    "__ia32_sys_lstat",
    "__ia32_sys_newstat",
    "__ia32_sys_newlstat",
    "__ia32_sys_getpriority",
    "__ia32_sys_newfstatat",

    /* BPF functions */
    "bpf_map_lookup_elem",
    "bpf_map_update_elem",
    "array_map_update_elem",
    "bpf_ringbuf_output",
    "bpf_ringbuf_reserve",
    "bpf_ringbuf_submit",
    "__bpf_prog_run",
    "perf_event_output",
    "perf_trace_run_bpf_submit",
    "bpf_iter_run_prog",
    "bpf_seq_write",
    "bpf_seq_printf",
    "__x64_sys_bpf",
    "__ia32_sys_bpf",

    NULL
};

/*
 * photon_is_watchlisted - return true if @name appears in photon_watchlist[].
 *
 * Defined static inline so each including translation unit gets an inlined
 * copy with no external linkage and no Makefile change required.
 */
static inline bool photon_is_watchlisted(const char *name)
{
    const char * const *entry;

    if (!name || !*name)
        return false;

    for (entry = photon_watchlist; *entry != NULL; entry++) {
        if (strcmp(*entry, name) == 0)
            return true;
    }

    return false;
}

#endif /* PHOTON_RING_WATCHLISTS_H */