# LKSM Elasticsearch Payload Structure

Documents are indexed into the `lksm_events` index.

## Example Document

```json
{
  "seq": 0,
  "@timestamp": "2026-02-27T21:34:09.440000+00:00",
  "ts": 12345.678,
  "type": "privilege_escalation",
  "severity": "critical",
  "source": "kprobe_reader",
  "data": {
    "message": "PRIVILEGE ESCALATION DETECTED: Process 'sudo' (PID 49814) becoming root via commit_creds!",
    "detector": "become_root_detector",
    "process_name": "sudo",
    "pid": 49814,
    "target_symbol": "commit_creds",
    "target_addr": "ffffffff812a4b60",
    "hook_mechanism": "ftrace",
    "symbol": "commit_creds"
  }
}
```

## Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `seq` | integer | Sequence number (assigned by registry) |
| `@timestamp` | date | UTC wall-clock time when the event was indexed |
| `ts` | double | Kernel monotonic timestamp from dmesg (seconds since boot) |
| `type` | keyword | Event type (see table below) |
| `severity` | keyword | `info`, `medium`, `high`, or `critical` |
| `source` | keyword | Always `kprobe_reader` (the parser module) |

## `data` Fields

| Field | Type | Present when |
|-------|------|-------------|
| `message` | text | Always — raw PHOTON RING message body |
| `detector` | keyword | Most structured events — which kernel detector produced it |
| `pid` | integer | Most structured events — PID of the process |
| `process_name` | keyword | Most structured events — process comm name |
| `target_symbol` | keyword | BPF, TCP, ICMP, and privilege escalation events — kernel function targeted |
| `target_addr` | keyword | BPF events only — hex address of the target function |
| `hook_mechanism` | keyword | BPF, TCP, ICMP, and privilege escalation events — hooking method used |
| `symbol` | keyword | `kprobe_registered` events only — the probed symbol name |
| `caller` | keyword | TCP, ICMP, kthread, and LKRG events — caller address/symbol |
| `thread_name` | keyword | `suspicious_kthread` — name of the suspicious kernel thread |
| `cleared_bits` | keyword | `taint_cleared` — hex bitmask of cleared taint bits |
| `old_mask` | keyword | `taint_cleared` — previous taint mask value |
| `new_mask` | keyword | `taint_cleared` — new taint mask value |
| `tgid` | integer | `hidden_task_detected` — thread group ID of hidden task |
| `target_file` | keyword | `ftrace_tamper` — ftrace control file being written to |
| `tracepoint` | keyword | `pid_hiding_hook` — tracepoint name being hooked |
| `probe_function` | keyword | `pid_hiding_hook` — address of the registered probe function |
| `path` | keyword | chdir, readlink, stat, and file access events — filesystem path |
| `flags` | keyword | `sensitive_file_access` — open flags (hex) |
| `mode` | keyword | `sensitive_file_access` — file mode (octal) |
| `ppid` | integer | `sensitive_file_access` — parent PID |
| `uid` | integer | `sensitive_file_access` — user ID |
| `gid` | integer | `sensitive_file_access` — group ID |
| `syscall` | keyword | `pid_hidden` — syscall that revealed the hiding (e.g. stat, lstat) |

## Event Types

| `type` | `severity` | `detector` | Triggered by |
|--------|-----------|------------|-------------|
| `bpf_hook_detected` | `critical` | `bpf_hook_detector` | ftrace hook on a BPF watchlist function |
| `tcp_hook_detected` | `critical` | `tcp_hiding_detector` | ftrace hook on TCP/UDP seq_show or tpacket_rcv |
| `icmp_hook_detected` | `critical` | `icmp_hook_detector` | ftrace hook on icmp_rcv (ICMP backdoor) |
| `suspicious_kthread` | `critical` | `reset_tainted_detector` | Suspicious kernel thread spawned (e.g. zer0t) |
| `taint_cleared` | `critical` | `reset_tainted_detector` | Kernel taint mask bits cleared unexpectedly |
| `hidden_task_detected` | `critical` | `reset_tainted_detector` | Hidden task found in kernel task list |
| `dmesg_cleared` | `critical` | `clear_taint_dmesg_detector` | Kernel ring buffer cleared (syslog type 5) |
| `ftrace_tamper` | `critical` | `hooks_write_detector` | Write to ftrace control file |
| `pid_hidden` | `critical` | `hiding_stat_detector` | PID exists in tasklist but /proc entry missing |
| `privilege_escalation` | `critical` | `become_root_detector` | Non-root process calling commit_creds with uid 0 |
| `pid_hiding_hook` | `high` | `trace_pid_detector` | Tracepoint probe on sched_process_fork/exec/exit |
| `sensitive_file_access` | `high` | `hook_file_access_detector` | Sensitive file opened (e.g. /etc/shadow, /root/.ssh) |
| `lkrg_bypass_attempt` | `high` | `lkrg_bypass_detector` | LKRG message detected in vprintk_emit |
| `suspicious_chdir` | `medium` | `hiding_chdir_detector` | chdir to sensitive path (/proc, /.hidden, /dev/shm) |
| `suspicious_readlink` | `medium` | `hiding_readlink_detector` | readlink on module path (.ko) or exe symlink |
| `suspicious_probe` | `high` | — | Generic SUSPICIOUS message (catch-all) |
| `ftrace_filter_registered` | `info` | `bpf_hook_detector` | ftrace hook on a non-watchlist function |
| `kprobe_registered` | `info` | — | Kprobe registration detected |
| `photon_ring_generic` | `info` | — | Any other PHOTON RING message (init, cleanup, etc.) |
