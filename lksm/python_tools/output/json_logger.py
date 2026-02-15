"""
EventLogger — writes LKSMEvents to daily JSONL files.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List

from python_tools.core.module_base import LKSMEvent


class EventLogger:
    """Appends events to ``data/logs/lksm_events_YYYY-MM-DD.jsonl``."""

    def __init__(self, config: dict):
        log_cfg = config.get("logging", {})
        self._output_dir = Path(log_cfg.get("output_dir", "data/logs"))
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _log_path(self) -> Path:
        today = datetime.now().strftime("%Y-%m-%d")
        return self._output_dir / f"lksm_events_{today}.jsonl"

    def log_event(self, event: LKSMEvent) -> None:
        with open(self._log_path(), "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def log_events(self, events: List[LKSMEvent]) -> None:
        if not events:
            return
        path = self._log_path()
        with open(path, "a") as f:
            for ev in events:
                f.write(json.dumps(ev.to_dict()) + "\n")
