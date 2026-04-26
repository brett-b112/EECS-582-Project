"""
KprobeReaderModule — reads [PHOTON RING] events from dmesg.
"""

import re
import subprocess
import time
from typing import List

from python_tools.core.module_base import LKSMEvent, MonitorModule

_PHOTON_RE = re.compile(
    r"\[\s*(?P<ts>[\d.]+)\]\s*\[PHOTON RING\]\s*(?P<msg>.*)"
)

_BPF_SUSPICIOUS_RE = re.compile(
    r"SUSPICIOUS \*\*\* ftrace hook on BPF function:\s*(\S+)\s*\(addr\s+([0-9a-fA-F]+)\)"
    r"(?:\s*by process '([^']+)'\s*\(PID\s*(\d+)\))?"
)

_BPF_FTRACE_RE = re.compile(
    r"ftrace filter registered for:\s*(\S+)\s*\(addr\s+([0-9a-fA-F]+)\)"
    r"(?:\s*by process '([^']+)'\s*\(PID\s*(\d+)\))?"
)

_PRIVESC_RE = re.compile(
    r"Process '([^']+)'\s*\(PID\s*(\d+)\)\s*becoming root via commit_creds"
)

# TCP hiding detector: ftrace hook on TCP/UDP seq_show or tpacket_rcv
_TCP_HOOK_RE = re.compile(
    r"SUSPICIOUS \*\*\* ftrace hook on (\S+) detected! Possible TCP hiding rootkit!"
    r"\s*\(caller:\s*(\S+)\)\s*by process '([^']+)'\s*\(PID\s*(\d+)\)"
)

# ICMP hook detector: ftrace hook on icmp_rcv
_ICMP_HOOK_RE = re.compile(
    r"SUSPICIOUS \*\*\* ftrace hook on (\S+) detected! Possible ICMP backdoor rootkit!"
    r"\s*\(caller:\s*(\S+)\)\s*by process '([^']+)'\s*\(PID\s*(\d+)\)"
)

# reset_tainted_detector: suspicious kthread spawned
_KTHREAD_RE = re.compile(
    r"SUSPICIOUS \*\*\* kthread '([^']+)' spawned! Caller:\s*(\S+),\s*process:\s*'([^']+)'\s*\(PID\s*(\d+)\)"
)

# reset_tainted_detector: tainted_mask cleared
_TAINT_CLEARED_RE = re.compile(
    r"SUSPICIOUS \*\*\* tainted_mask cleared! Cleared bits:\s*0x([0-9a-fA-F]+)\s*\(was:\s*0x([0-9a-fA-F]+),\s*now:\s*0x([0-9a-fA-F]+)\)"
)

# reset_tainted_detector: hidden task in task list
_HIDDEN_TASK_RE = re.compile(
    r"SUSPICIOUS \*\*\* suspicious task found in kernel task list:\s*'([^']+)'\s*\(PID\s*(\d+),\s*TGID\s*(\d+)\)"
)

# clear_taint_dmesg_detector: kernel ring buffer clear
_DMESG_CLEAR_RE = re.compile(
    r"SUSPICIOUS \*\*\* kernel ring buffer CLEAR \(syslog type 5\) by process '([^']+)'\s*\(PID\s*(\d+)\)"
)

# trace_pid_detector: tracepoint probe for PID hiding
_TRACE_PID_RE = re.compile(
    r"SUSPICIOUS \*\*\* tracepoint probe registered on '([^']+)' by process '([^']+)'\s*\(PID\s*(\d+)\),\s*probe function at\s*(\S+)"
)

# hiding_chdir_detector: chdir to sensitive path
_CHDIR_RE = re.compile(
    r"SUSPICIOUS \*\*\* chdir to sensitive path '([^']+)' by process '([^']+)'\s*\(PID\s*(\d+)\)"
)

# hooks_write_detector: write to ftrace control file
_FTRACE_WRITE_RE = re.compile(
    r"SUSPICIOUS \*\*\* write to ftrace control file '([^']+)' by process '([^']+)'\s*\(PID\s*(\d+)\)"
)

# hiding_readlink_detector: readlink on sensitive path
_READLINK_RE = re.compile(
    r"SUSPICIOUS \*\*\* readlink on sensitive path '([^']+)' by process '([^']+)'\s*\(PID\s*(\d+)\)"
)

# hiding_stat: PID exists in tasklist but /proc entry missing
_PID_HIDDEN_RE = re.compile(
    r"CRITICAL:\s*(\S+)\(\"([^\"]+)\"\)\s*-\s*PID\s*(\d+)\s*exists in tasklist but /proc entry missing"
)

# hook_file_access: sensitive file open
_FILE_OPEN_RE = re.compile(
    r'FILE_OPEN path="([^"]+)" flags=0x([0-9a-fA-F]+) mode=(\S+)'
    r' pid=(\d+) ppid=(\d+) uid=(\d+) gid=(\d+) comm="([^"]+)"'
)

# lkrg_bypass_detector: LKRG message filtering
_LKRG_BYPASS_RE = re.compile(
    r"LKRG message detected in vprintk_emit from caller\s*(\S+),\s*process '([^']+)'\s*\(PID\s*(\d+)\)"
)


class KprobeReaderModule(MonitorModule):
    """Polls dmesg for [PHOTON RING] lines and converts them to LKSMEvents."""

    def __init__(self):
        self._last_ts: float = 0.0
        self._seen: set = set()
        self._running: bool = False

    @property
    def name(self) -> str:
        return "kprobe_reader"

    def start(self, config: dict) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def poll(self) -> List[LKSMEvent]:
        if not self._running:
            return []

        try:
            result = subprocess.run(
                ["dmesg", "--decode"],
                capture_output=True, text=True, timeout=5,
            )
            lines = result.stdout.splitlines()
        except (subprocess.SubprocessError, FileNotFoundError):
            return []

        events: List[LKSMEvent] = []
        for line in lines:
            m = _PHOTON_RE.search(line)
            if not m:
                continue

            ts = float(m.group("ts"))
            if ts < self._last_ts:
                continue

            msg = m.group("msg").strip()

            dedup_key = (ts, msg)
            if dedup_key in self._seen:
                continue
            self._seen.add(dedup_key)

            severity, ev_type, data = _parse_message(msg)
            data.setdefault("message", msg)

            events.append(LKSMEvent(
                seq=0,          # registry assigns final seq
                ts=ts,
                type=ev_type,
                data=data,
                severity=severity,
                source="kprobe_reader",
            ))

        return events


def _parse_message(msg: str):
    """Return (severity, type, data-dict) from a PHOTON RING message body."""
    # BPF hook detector: suspicious hook on a watched BPF function
    bpf_sus = _BPF_SUSPICIOUS_RE.search(msg)
    if bpf_sus:
        data = {
            "detector": "bpf_hook_detector",
            "target_symbol": bpf_sus.group(1),
            "target_addr": bpf_sus.group(2),
            "hook_mechanism": "ftrace",
        }
        if bpf_sus.group(3):
            data["process_name"] = bpf_sus.group(3)
        if bpf_sus.group(4):
            data["pid"] = int(bpf_sus.group(4))
        return "critical", "bpf_hook_detected", data

    # BPF hook detector: informational ftrace filter registration
    bpf_ft = _BPF_FTRACE_RE.search(msg)
    if bpf_ft:
        data = {
            "detector": "bpf_hook_detector",
            "target_symbol": bpf_ft.group(1),
            "target_addr": bpf_ft.group(2),
            "hook_mechanism": "ftrace",
        }
        if bpf_ft.group(3):
            data["process_name"] = bpf_ft.group(3)
        if bpf_ft.group(4):
            data["pid"] = int(bpf_ft.group(4))
        return "info", "ftrace_filter_registered", data

    # become_root_detector: privilege escalation
    privesc = _PRIVESC_RE.search(msg)
    if privesc:
        return "critical", "privilege_escalation", {
            "detector": "become_root_detector",
            "process_name": privesc.group(1),
            "pid": int(privesc.group(2)),
            "target_symbol": "commit_creds",
            "hook_mechanism": "ftrace",
        }

    # TCP hiding detector
    tcp = _TCP_HOOK_RE.search(msg)
    if tcp:
        return "critical", "tcp_hook_detected", {
            "detector": "tcp_hiding_detector",
            "target_symbol": tcp.group(1),
            "caller": tcp.group(2),
            "process_name": tcp.group(3),
            "pid": int(tcp.group(4)),
            "hook_mechanism": "ftrace",
        }

    # ICMP hook detector
    icmp = _ICMP_HOOK_RE.search(msg)
    if icmp:
        return "critical", "icmp_hook_detected", {
            "detector": "icmp_hook_detector",
            "target_symbol": icmp.group(1),
            "caller": icmp.group(2),
            "process_name": icmp.group(3),
            "pid": int(icmp.group(4)),
            "hook_mechanism": "ftrace",
        }

    # reset_tainted_detector: suspicious kthread
    kthread = _KTHREAD_RE.search(msg)
    if kthread:
        return "critical", "suspicious_kthread", {
            "detector": "reset_tainted_detector",
            "thread_name": kthread.group(1),
            "caller": kthread.group(2),
            "process_name": kthread.group(3),
            "pid": int(kthread.group(4)),
        }

    # reset_tainted_detector: taint mask cleared
    taint = _TAINT_CLEARED_RE.search(msg)
    if taint:
        return "critical", "taint_cleared", {
            "detector": "reset_tainted_detector",
            "cleared_bits": taint.group(1),
            "old_mask": taint.group(2),
            "new_mask": taint.group(3),
        }

    # reset_tainted_detector: hidden task
    hidden = _HIDDEN_TASK_RE.search(msg)
    if hidden:
        return "critical", "hidden_task_detected", {
            "detector": "reset_tainted_detector",
            "process_name": hidden.group(1),
            "pid": int(hidden.group(2)),
            "tgid": int(hidden.group(3)),
        }

    # clear_taint_dmesg_detector: dmesg cleared
    dmesg_clr = _DMESG_CLEAR_RE.search(msg)
    if dmesg_clr:
        return "critical", "dmesg_cleared", {
            "detector": "clear_taint_dmesg_detector",
            "process_name": dmesg_clr.group(1),
            "pid": int(dmesg_clr.group(2)),
        }

    # hooks_write_detector: ftrace control file tampered
    ftrace_w = _FTRACE_WRITE_RE.search(msg)
    if ftrace_w:
        return "critical", "ftrace_tamper", {
            "detector": "hooks_write_detector",
            "target_file": ftrace_w.group(1),
            "process_name": ftrace_w.group(2),
            "pid": int(ftrace_w.group(3)),
        }

    # trace_pid_detector: PID-hiding tracepoint hook
    tpid = _TRACE_PID_RE.search(msg)
    if tpid:
        return "high", "pid_hiding_hook", {
            "detector": "trace_pid_detector",
            "tracepoint": tpid.group(1),
            "process_name": tpid.group(2),
            "pid": int(tpid.group(3)),
            "probe_function": tpid.group(4),
        }

    # hiding_chdir_detector: chdir to sensitive path
    chdir = _CHDIR_RE.search(msg)
    if chdir:
        return "medium", "suspicious_chdir", {
            "detector": "hiding_chdir_detector",
            "path": chdir.group(1),
            "process_name": chdir.group(2),
            "pid": int(chdir.group(3)),
        }

    # hiding_readlink_detector: readlink on sensitive path
    rdlink = _READLINK_RE.search(msg)
    if rdlink:
        return "medium", "suspicious_readlink", {
            "detector": "hiding_readlink_detector",
            "path": rdlink.group(1),
            "process_name": rdlink.group(2),
            "pid": int(rdlink.group(3)),
        }

    # hiding_stat: PID hidden at VFS level
    pidhide = _PID_HIDDEN_RE.search(msg)
    if pidhide:
        return "critical", "pid_hidden", {
            "detector": "hiding_stat_detector",
            "syscall": pidhide.group(1),
            "path": pidhide.group(2),
            "pid": int(pidhide.group(3)),
        }

    # hook_file_access: sensitive file opened
    fopen = _FILE_OPEN_RE.search(msg)
    if fopen:
        return "high", "sensitive_file_access", {
            "detector": "hook_file_access_detector",
            "path": fopen.group(1),
            "flags": fopen.group(2),
            "mode": fopen.group(3),
            "pid": int(fopen.group(4)),
            "ppid": int(fopen.group(5)),
            "uid": int(fopen.group(6)),
            "gid": int(fopen.group(7)),
            "process_name": fopen.group(8),
        }

    # lkrg_bypass_detector: LKRG bypass attempt
    lkrg = _LKRG_BYPASS_RE.search(msg)
    if lkrg:
        return "high", "lkrg_bypass_attempt", {
            "detector": "lkrg_bypass_detector",
            "caller": lkrg.group(1),
            "process_name": lkrg.group(2),
            "pid": int(lkrg.group(3)),
        }

    # Generic suspicious probe (non-BPF) — catch-all for any remaining SUSPICIOUS messages
    if "SUSPICIOUS" in msg:
        return "high", "suspicious_probe", {"message": msg}

    sym_match = re.search(r"Kprobe registered for symbol:\s*(\S+)", msg)
    if sym_match:
        return "info", "kprobe_registered", {"symbol": sym_match.group(1)}

    return "info", "photon_ring_generic", {"message": msg}


def create_module() -> KprobeReaderModule:
    """Factory used by ModuleRegistry.discover()."""
    return KprobeReaderModule()
