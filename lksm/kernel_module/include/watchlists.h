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

    /* -----------------------------------------------------------------------
     * hiding_directory.c — directory entry hiding via getdents hooks
     * --------------------------------------------------------------------- */
    "__x64_sys_getdents64",
    "__x64_sys_getdents",
    "__ia32_sys_getdents64",
    "__ia32_sys_getdents",
    "__ia32_compat_sys_getdents",
    /* generic variants */
    "getdents64",
    "getdents",
    "sys_getdents64",
    "sys_getdents",
    "filldir64",
    "filldir",
    "iterate_dir",

    /* -----------------------------------------------------------------------
     * hiding_readlink.c — readlink syscall hooks
     * --------------------------------------------------------------------- */
    "__x64_sys_readlink",
    "__ia32_sys_readlink",
    "sys_readlink",

    /* -----------------------------------------------------------------------
     * hiding_chdir.c — chdir syscall hooks
     * --------------------------------------------------------------------- */
    "__x64_sys_chdir",
    "__ia32_sys_chdir",
    "sys_chdir",

    /* -----------------------------------------------------------------------
     * open.c — openat / readlinkat / access hooks
     * --------------------------------------------------------------------- */
    "__x64_sys_openat",
    "__ia32_sys_openat",
    "__ia32_compat_sys_openat",
    "__x64_sys_readlinkat",
    "__ia32_sys_readlinkat",
    "__x64_sys_access",
    "__ia32_sys_access",
    "__x64_sys_faccessat",
    "__ia32_sys_faccessat",
    "__x64_sys_faccessat2",
    "__ia32_sys_faccessat2",
    "sys_openat",
    "sys_access",
    "sys_faccessat",

    /* -----------------------------------------------------------------------
     * hiding_stat.c — stat family syscall hooks
     * --------------------------------------------------------------------- */
    "__x64_sys_statx",
    "__ia32_sys_statx",
    "__x64_sys_stat",
    "__ia32_sys_stat",
    "__x64_sys_lstat",
    "__ia32_sys_lstat",
    "__x64_sys_newstat",
    "__ia32_sys_newstat",
    "__x64_sys_newlstat",
    "__ia32_sys_newlstat",
    "__x64_sys_getpriority",
    "__ia32_sys_getpriority",
    "__x64_sys_newfstatat",
    "__ia32_sys_newfstatat",
    /* generic variants */
    "sys_stat",
    "sys_lstat",
    "sys_newstat",
    "sys_newlstat",
    "sys_statx",
    "sys_newfstatat",

    /* -----------------------------------------------------------------------
     * become_root.c — privilege escalation via signal / scheduler hooks
     * --------------------------------------------------------------------- */
    "__x64_sys_kill",
    "__x64_sys_getpgid",
    "__x64_sys_getpgrp",
    "__x64_sys_getsid",
    "__x64_sys_sched_getaffinity",
    "__x64_sys_sched_getparam",
    "__x64_sys_sched_getscheduler",
    "__x64_sys_sched_rr_get_interval",
    "__x64_sys_sysinfo",
    "__x64_sys_pidfd_open",
    /* generic variants */
    "do_send_sig_info",
    "commit_creds",
    "prepare_kernel_cred",
    "cap_capable",
    "sys_kill",

    /* -----------------------------------------------------------------------
     * task.c — taskstats hook (process hiding via netlink)
     * --------------------------------------------------------------------- */
    "taskstats_user_cmd",

    /* -----------------------------------------------------------------------
     * hiding_tcp.c — network connection hiding
     * --------------------------------------------------------------------- */
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "tpacket_rcv",

    /* -----------------------------------------------------------------------
     * audit.c — audit log and netlink suppression
     * --------------------------------------------------------------------- */
    "audit_log_start",
    "netlink_unicast",
    "__x64_sys_recvmsg",
    "__x64_sys_recvfrom",
    "__ia32_sys_recvmsg",
    "__ia32_sys_recvfrom",
    "sys_recvmsg",
    "sys_recvfrom",

    /* -----------------------------------------------------------------------
     * bpf_hook.c — BPF subsystem hooks (evade eBPF-based detectors)
     * --------------------------------------------------------------------- */
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

    /* -----------------------------------------------------------------------
     * hooks_write.c — write family syscall hooks (output suppression)
     * --------------------------------------------------------------------- */
    "__x64_sys_write",
    "__ia32_sys_write",
    "__x64_sys_writev",
    "__ia32_sys_writev",
    "__x64_sys_pwrite64",
    "__x64_sys_ia32_pwrite64",
    "__ia32_sys_pwrite64",
    "__ia32_compat_sys_pwrite64",
    "__x64_sys_pwritev",
    "__x64_sys_pwritev2",
    "__ia32_sys_pwritev",
    "__ia32_sys_pwritev2",
    "__x64_sys_sendfile",
    "__x64_sys_sendfile64",
    "__ia32_sys_sendfile",
    "__ia32_sys_sendfile64",
    "__ia32_compat_sys_sendfile",
    "__ia32_compat_sys_sendfile64",
    "__x64_sys_copy_file_range",
    "__ia32_sys_copy_file_range",
    "__x64_sys_splice",
    "__ia32_sys_splice",
    "__x64_sys_vmsplice",
    "__ia32_sys_vmsplice",
    "__x64_sys_tee",
    "__ia32_sys_tee",
    "__x64_sys_io_uring_enter",
    "__ia32_sys_io_uring_enter",
    /* generic variants */
    "sys_write",
    "sys_writev",
    "sys_pwrite64",

    /* -----------------------------------------------------------------------
     * clear_taint_dmesg.c — read family hooks (dmesg / log suppression)
     * --------------------------------------------------------------------- */
    "__x64_sys_read",
    "__ia32_sys_read",
    "__x64_sys_pread64",
    "__ia32_sys_pread64",
    "__x64_sys_readv",
    "__ia32_sys_readv",
    "__x64_sys_preadv",
    "__ia32_sys_preadv",
    "do_syslog",
    "sched_debug_show",
    /* generic variants */
    "sys_read",
    "sys_readv",
    "sys_pread64",

    /* -----------------------------------------------------------------------
     * icmp.c — ICMP covert channel + SELinux enforcement hooks
     * --------------------------------------------------------------------- */
    "icmp_rcv",
    "sel_read_enforce",
    "sel_write_enforce",

    /* -----------------------------------------------------------------------
     * lkrg_bypass.c — LKRG integrity monitor bypass
     * These are LKRG-internal symbols; any lookup is unambiguously hostile.
     * --------------------------------------------------------------------- */
    "vprintk_emit",
    "call_usermodehelper_exec_async",
    "call_usermodehelper_exec",
    "p_ed_enforce_validation",
    "p_ed_enforce_validation_paranoid",
    "p_ed_validate_current",
    "p_ed_validate_off_flag_wrap",
    "p_ed_enforce_pcfi",

    /* -----------------------------------------------------------------------
     * sysrq_hook.c — task dump / OOM output suppression
     * --------------------------------------------------------------------- */
    "sched_show_task",
    "dump_header",
    "print_task.isra.0",

    /* -----------------------------------------------------------------------
     * selfdefense.c — anti-forensic / anti-analysis hooks
     * --------------------------------------------------------------------- */
    "copy_from_kernel_nofault",
    "kallsyms_on_each_symbol",
    "__module_address",
    "find_module",
    "walk_system_ram_res",
    "walk_iomem_res_desc",
    "kmap_atomic",
    "kmap_local_page",
    /* generic variants */
    "module_alloc",
    "set_memory_x",
    "ftrace_ops_list",
    "kthread_create_on_node",
    "proc_pid_readdir",
    "proc_pid_lookup",

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