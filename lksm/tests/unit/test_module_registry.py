"""
Tests for ModuleRegistry, KprobeReaderModule, dashboard, and JSON logger.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from python_tools.core.module_base import LKSMEvent, ModuleRegistry, MonitorModule
from python_tools.core.modules.kprobe_reader import KprobeReaderModule, _parse_message
from python_tools.output.dashboard import create_app, push_events, _events, _lock
from python_tools.output.json_logger import EventLogger


# --------------- Registry tests ---------------

class FakeModule(MonitorModule):
    @property
    def name(self):
        return "fake"

    def start(self, config):
        pass

    def stop(self):
        pass

    def poll(self):
        return [
            LKSMEvent(seq=0, ts=1.0, type="test", data={"k": "v"}, source="fake"),
        ]


def test_register_and_poll():
    reg = ModuleRegistry()
    reg.register(FakeModule())
    assert "fake" in reg.module_names
    events = reg.poll_all()
    assert len(events) == 1
    assert events[0].source == "fake"
    assert events[0].seq == 0


def test_poll_assigns_sequential_ids():
    reg = ModuleRegistry()
    reg.register(FakeModule())
    first = reg.poll_all()
    second = reg.poll_all()
    assert first[0].seq == 0
    assert second[0].seq == 1


# --------------- KprobeReader parse tests ---------------

def test_parse_kprobe_registered():
    sev, etype, data = _parse_message("Kprobe registered for symbol: do_init_module")
    assert sev == "info"
    assert etype == "kprobe_registered"
    assert data["symbol"] == "do_init_module"


def test_parse_suspicious():
    sev, etype, data = _parse_message("SUSPICIOUS *** kallsyms_lookup_name probe detected!")
    assert sev == "high"
    assert etype == "suspicious_probe"
    assert "SUSPICIOUS" in data["message"]


def test_parse_generic():
    sev, etype, data = _parse_message("Something else entirely")
    assert sev == "info"
    assert etype == "photon_ring_generic"


# --------------- KprobeReader dmesg integration ---------------

FAKE_DMESG = """\
kern  :info  : [  120.001234] [PHOTON RING] Kprobe registered for symbol: do_init_module
kern  :warn  : [  120.002345] [PHOTON RING] SUSPICIOUS *** kallsyms_lookup_name probe detected!
kern  :info  : [  130.000000] some unrelated line
"""


@patch("python_tools.core.modules.kprobe_reader.subprocess.run")
def test_kprobe_reader_poll(mock_run):
    mock_run.return_value = MagicMock(stdout=FAKE_DMESG)

    reader = KprobeReaderModule()
    reader.start({})

    events = reader.poll()
    assert len(events) == 2
    assert events[0].type == "kprobe_registered"
    assert events[0].data["symbol"] == "do_init_module"
    assert events[1].type == "suspicious_probe"
    assert events[1].severity == "high"


@patch("python_tools.core.modules.kprobe_reader.subprocess.run")
def test_kprobe_reader_deduplicates(mock_run):
    mock_run.return_value = MagicMock(stdout=FAKE_DMESG)

    reader = KprobeReaderModule()
    reader.start({})

    first = reader.poll()
    assert len(first) == 2

    # Same dmesg output → no new events
    second = reader.poll()
    assert len(second) == 0


FAKE_DMESG_SAME_TS = """\
kern  :info  : [  120.001234] [PHOTON RING] Kprobe registered for symbol: do_init_module
kern  :warn  : [  120.001234] [PHOTON RING] SUSPICIOUS *** kallsyms_lookup_name probe detected!
"""


@patch("python_tools.core.modules.kprobe_reader.subprocess.run")
def test_kprobe_reader_same_timestamp_different_msg(mock_run):
    """Events with identical timestamps but different messages are both captured."""
    mock_run.return_value = MagicMock(stdout=FAKE_DMESG_SAME_TS)

    reader = KprobeReaderModule()
    reader.start({})

    events = reader.poll()
    assert len(events) == 2
    assert events[0].type == "kprobe_registered"
    assert events[1].type == "suspicious_probe"


# --------------- Dashboard smoke tests ---------------

@pytest.fixture()
def dashboard_client():
    """Yield a Flask test client with a clean event deque."""
    with _lock:
        _events.clear()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
    with _lock:
        _events.clear()


def test_dashboard_index_returns_html(dashboard_client):
    resp = dashboard_client.get("/")
    assert resp.status_code == 200
    assert resp.content_type == "text/html"
    assert b"LKSM Monitoring Dashboard" in resp.data


def test_api_events_empty(dashboard_client):
    resp = dashboard_client.get("/api/events")
    assert resp.status_code == 200
    assert resp.json == []


def test_api_events_after_push(dashboard_client):
    ev = LKSMEvent(seq=0, ts=1.0, type="test", data={"k": "v"}, source="fake")
    push_events([ev])
    resp = dashboard_client.get("/api/events")
    assert resp.status_code == 200
    events = resp.json
    assert len(events) == 1
    assert events[0]["type"] == "test"
    assert events[0]["data"] == {"k": "v"}


def test_api_events_respects_maxlen(dashboard_client):
    """Deque maxlen is 500 — pushing 502 events should keep only the last 500."""
    evs = [
        LKSMEvent(seq=i, ts=float(i), type="bulk", data={"i": i}, source="test")
        for i in range(502)
    ]
    push_events(evs)
    resp = dashboard_client.get("/api/events")
    data = resp.json
    assert len(data) == 500
    assert data[0]["seq"] == 2   # first two evicted


# --------------- JSON logger smoke tests ---------------

def test_logger_creates_jsonl(tmp_path):
    config = {"logging": {"output_dir": str(tmp_path / "logs")}}
    logger = EventLogger(config)

    ev = LKSMEvent(seq=0, ts=42.0, type="test_log", data={"x": 1}, source="unit")
    logger.log_event(ev)

    files = list((tmp_path / "logs").glob("*.jsonl"))
    assert len(files) == 1
    line = files[0].read_text().strip()
    record = json.loads(line)
    assert record["type"] == "test_log"
    assert record["ts"] == 42.0


def test_logger_log_events_batch(tmp_path):
    config = {"logging": {"output_dir": str(tmp_path / "logs")}}
    logger = EventLogger(config)

    evs = [
        LKSMEvent(seq=i, ts=float(i), type="batch", data={"i": i}, source="unit")
        for i in range(3)
    ]
    logger.log_events(evs)

    files = list((tmp_path / "logs").glob("*.jsonl"))
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 3
    for i, line in enumerate(lines):
        assert json.loads(line)["seq"] == i


def test_logger_skips_empty_list(tmp_path):
    config = {"logging": {"output_dir": str(tmp_path / "logs")}}
    logger = EventLogger(config)
    logger.log_events([])
    # No file should be created when nothing is logged
    files = list((tmp_path / "logs").glob("*.jsonl"))
    assert len(files) == 0
