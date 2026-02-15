"""
LKSM Module Base — event model, monitor ABC, and module registry.
"""

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class LKSMEvent:
    """A single event produced by a monitor module."""
    seq: int
    ts: float
    type: str
    data: Dict[str, Any]
    severity: str = "info"       # info | medium | high | critical
    source: str = "unknown"

    def to_dict(self) -> dict:
        return asdict(self)


class MonitorModule(ABC):
    """Abstract base class every monitor module must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def start(self, config: dict) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def poll(self) -> List[LKSMEvent]:
        ...


class ModuleRegistry:
    """Discovers, registers, and polls monitor modules."""

    def __init__(self):
        self._modules: Dict[str, MonitorModule] = {}
        self._seq: int = 0

    def register(self, module: MonitorModule) -> None:
        self._modules[module.name] = module

    def discover(self, package_path: str) -> None:
        """Import every sub-module in *package_path* and call create_module()."""
        pkg = importlib.import_module(package_path)
        for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"{package_path}.{modname}")
            factory = getattr(mod, "create_module", None)
            if callable(factory):
                self.register(factory())

    def start_all(self, config: dict) -> None:
        for m in self._modules.values():
            m.start(config)

    def stop_all(self) -> None:
        for m in self._modules.values():
            m.stop()

    def poll_all(self) -> List[LKSMEvent]:
        events: List[LKSMEvent] = []
        for m in self._modules.values():
            for ev in m.poll():
                ev.seq = self._seq
                self._seq += 1
                events.append(ev)
        return events

    @property
    def module_names(self) -> List[str]:
        return list(self._modules.keys())
