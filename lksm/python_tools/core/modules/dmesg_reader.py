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


class KprobeReaderModule(MonitorModule):
    """Polls dmesg for [PHOTON RING] lines and converts them to LKSMEvents."""

    def __init__(self):
        self._last_ts: float = 0.0
        self._seen_at_last_ts: set = set()
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

            if ts == self._last_ts and msg in self._seen_at_last_ts:
                continue
            severity, ev_type, data = _parse_message(msg)

            events.append(LKSMEvent(
                seq=0,          # registry assigns final seq
                ts=ts,
                type=ev_type,
                data=data,
                severity=severity,
                source="kprobe_reader",
            ))

        if events:
            new_last_ts = events[-1].ts
            if new_last_ts > self._last_ts:
                self._last_ts = new_last_ts
                self._seen_at_last_ts = set()
            for ev in events:
                if ev.ts == self._last_ts:
                    self._seen_at_last_ts.add(ev.data.get("message", ev.data.get("symbol", "")))

        return events


def _parse_message(msg: str):
    """Return (severity, type, data-dict) from a PHOTON RING message body."""
    # BPF-specific SUSPICIOUS check (must come before generic SUSPICIOUS catch-all)
    bpf_hook_match = re.search(
        r"SUSPICIOUS \*\*\* ftrace hook on BPF function:\s*(\S+)\s*\(addr\s+([0-9a-fA-F]+)\)",
        msg,
    )
    if bpf_hook_match:
        return "high", "suspicious_bpf_hook", {
            "message": msg,
            "symbol": bpf_hook_match.group(1),
            "address": bpf_hook_match.group(2),
        }

    ftrace_filter_match = re.search(
        r"ftrace filter registered for:\s*(\S+)\s*\(addr\s+([0-9a-fA-F]+)\)",
        msg,
    )
    if ftrace_filter_match:
        return "info", "ftrace_filter_registered", {
            "message": msg,
            "symbol": ftrace_filter_match.group(1),
            "address": ftrace_filter_match.group(2),
        }

    if "SUSPICIOUS" in msg:
        # e.g. "SUSPICIOUS *** kallsyms_lookup_name probe detected!"
        return "high", "suspicious_probe", {"message": msg}

    sym_match = re.search(r"Kprobe registered for symbol:\s*(\S+)", msg)
    if sym_match:
        return "info", "kprobe_registered", {"symbol": sym_match.group(1)}

    return "info", "photon_ring_generic", {"message": msg}


def create_module() -> KprobeReaderModule:
    """Factory used by ModuleRegistry.discover()."""
    return KprobeReaderModule()
