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

    # Generic suspicious probe (non-BPF)
    if "SUSPICIOUS" in msg:
        return "high", "suspicious_probe", {"message": msg}

    sym_match = re.search(r"Kprobe registered for symbol:\s*(\S+)", msg)
    if sym_match:
        return "info", "kprobe_registered", {"symbol": sym_match.group(1)}

    return "info", "photon_ring_generic", {"message": msg}


def create_module() -> KprobeReaderModule:
    """Factory used by ModuleRegistry.discover()."""
    return KprobeReaderModule()
