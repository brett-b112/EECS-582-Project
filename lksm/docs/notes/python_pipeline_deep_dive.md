# LKSM Python Pipeline — Deep Dive

## File Structure

```
python_tools/
├── __init__.py
├── main.py                          # Entry point — CLI, daemon loop, Flask startup
├── core/
│   ├── __init__.py
│   ├── module_base.py               # LKSMEvent dataclass, MonitorModule ABC, ModuleRegistry
│   └── modules/
│       ├── __init__.py
│       └── kprobe_reader.py         # Concrete module — reads dmesg, parses [PHOTON RING]
└── output/
    ├── __init__.py
    ├── json_logger.py               # Writes LKSMEvents to daily .jsonl files
    └── dashboard.py                 # Flask app — serves HTML + JSON API
```

The separation is intentional: `core/` owns the data model and the plugin system,
`core/modules/` holds concrete input sources, and `output/` holds everything that
consumes events (disk logging, web UI). `main.py` is the only file that ties them
together.

---

## Layer 1: The Data Model — `module_base.py`

### `LKSMEvent` (lines 13-23)

```python
@dataclass
class LKSMEvent:
    seq: int                    # Global sequence number (assigned by registry)
    ts: float                   # Timestamp from dmesg (seconds since boot)
    type: str                   # e.g. "kprobe_registered", "suspicious_probe"
    data: Dict[str, Any]        # Flexible payload — {"symbol": "do_init_module"} etc.
    severity: str = "info"      # info | medium | high | critical
    source: str = "unknown"     # Which module produced this event
```

This is a Python `dataclass`. The `@dataclass` decorator auto-generates `__init__`,
`__repr__`, and `__eq__` from the field declarations. The key method is `to_dict()`
which calls `dataclasses.asdict(self)` — this recursively converts the dataclass and
all nested fields into a plain `dict`. That dict is what gets serialized to JSON
everywhere downstream.

For example, an event becomes:
```python
{
    "seq": 0,
    "ts": 120.001234,
    "type": "kprobe_registered",
    "data": {"symbol": "do_init_module"},
    "severity": "info",
    "source": "kprobe_reader"
}
```

### `MonitorModule` ABC (lines 26-44)

This is an abstract base class (ABC). It defines the contract every input module
must follow:

- `name` (property) — unique string identifier
- `start(config)` — called once after discovery, receives the YAML config dict
- `stop()` — cleanup
- `poll() -> List[LKSMEvent]` — called repeatedly by the daemon loop, returns zero
  or more new events

Any class that subclasses `MonitorModule` **must** implement all four, or Python
raises `TypeError` at instantiation time. This is how the plugin system enforces a
consistent interface.

### `ModuleRegistry` (lines 47-85)

This is the plugin manager. It has three responsibilities:

**1. Auto-discovery (`discover()`, lines 57-64):**
```python
def discover(self, package_path: str) -> None:
    pkg = importlib.import_module(package_path)
    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"{package_path}.{modname}")
        factory = getattr(mod, "create_module", None)
        if callable(factory):
            self.register(factory())
```

When called with `"python_tools.core.modules"`, it:
1. Imports the `python_tools.core.modules` package
2. Uses `pkgutil.iter_modules()` to scan every `.py` file in that directory
   (finds `kprobe_reader`)
3. Imports each one (`python_tools.core.modules.kprobe_reader`)
4. Looks for a `create_module()` function at module-level
5. If found, calls it to get a `MonitorModule` instance and registers it

This means you never have to manually wire up new modules. Drop a `.py` file with
`create_module()` into `core/modules/` and it's automatically picked up.

**2. Lifecycle (`start_all()` / `stop_all()`):**
Iterates all registered modules and calls `start(config)` or `stop()`.

**3. Polling (`poll_all()`, lines 74-81):**
```python
def poll_all(self) -> List[LKSMEvent]:
    events: List[LKSMEvent] = []
    for m in self._modules.values():
        for ev in m.poll():
            ev.seq = self._seq
            self._seq += 1
            events.append(ev)
    return events
```

Calls `poll()` on every module, collects all returned events, and stamps each one
with a globally unique, monotonically increasing sequence number. The modules
themselves set `seq=0` as a placeholder — the registry overwrites it here. This
guarantees ordering across all modules.

---

## Layer 2: Reading dmesg — `kprobe_reader.py`

This is the first (and currently only) concrete module.

### The regex (line 12-14)

```python
_PHOTON_RE = re.compile(
    r"\[\s*(?P<ts>[\d.]+)\]\s*\[PHOTON RING\]\s*(?P<msg>.*)"
)
```

A dmesg line with `--decode` looks like:
```
kern  :info  : [  120.001234] [PHOTON RING] Kprobe registered for symbol: do_init_module
```

The regex doesn't anchor to start-of-line — it uses `.search()`, so it skips the
`kern  :info  :` prefix and matches from the `[` of the timestamp. Named groups:
- `ts` — captures `120.001234` (seconds since boot, as a float)
- `msg` — captures everything after `[PHOTON RING] `, e.g.
  `Kprobe registered for symbol: do_init_module`

### The poll loop (lines 34-72)

```python
def poll(self) -> List[LKSMEvent]:
    # 1. Shell out to dmesg
    result = subprocess.run(
        ["dmesg", "--decode"],
        capture_output=True, text=True, timeout=5,
    )
    lines = result.stdout.splitlines()

    # 2. Filter and parse
    events = []
    for line in lines:
        m = _PHOTON_RE.search(line)
        if not m:
            continue                    # Not a PHOTON RING line — skip

        ts = float(m.group("ts"))
        if ts <= self._last_ts:
            continue                    # Already seen this event — skip

        msg = m.group("msg").strip()
        severity, ev_type, data = _parse_message(msg)

        events.append(LKSMEvent(
            seq=0,
            ts=ts,
            type=ev_type,
            data=data,
            severity=severity,
            source="kprobe_reader",
        ))

    # 3. Advance the watermark
    if events:
        self._last_ts = events[-1].ts

    return events
```

Key details:

- **Every poll reads the entire dmesg buffer.** `dmesg` dumps the whole kernel ring
  buffer each time. There's no "since last read" flag.
- **Deduplication is timestamp-based.** `self._last_ts` stores the timestamp of the
  most recent event we've already processed. On the next poll, any line with
  `ts <= self._last_ts` is skipped. Since kernel timestamps are monotonically
  increasing, this guarantees we only return genuinely new events.
- **`--decode` flag** adds the `kern  :info  :` facility/level prefix. The regex
  handles this by not anchoring to start-of-line.
- **Error handling** — if `dmesg` fails (permissions, timeout, not found), the
  `except` block returns an empty list. The daemon loop keeps running and tries
  again next cycle.

### Message parsing (lines 75-85)

```python
def _parse_message(msg: str):
    if "SUSPICIOUS" in msg:
        return "high", "suspicious_probe", {"message": msg}

    sym_match = re.search(r"Kprobe registered for symbol:\s*(\S+)", msg)
    if sym_match:
        return "info", "kprobe_registered", {"symbol": sym_match.group(1)}

    return "info", "photon_ring_generic", {"message": msg}
```

Three branches matching the two known `printk` formats from the kernel module, plus
a catch-all:

1. `"SUSPICIOUS *** kallsyms_lookup_name probe detected!"` — severity `high`, type
   `suspicious_probe`, data carries the raw message
2. `"Kprobe registered for symbol: do_init_module"` — severity `info`, type
   `kprobe_registered`, data carries the extracted symbol name
3. Anything else with `[PHOTON RING]` — severity `info`, type
   `photon_ring_generic`

### The factory (lines 88-90)

```python
def create_module() -> KprobeReaderModule:
    return KprobeReaderModule()
```

This is what `ModuleRegistry.discover()` looks for. It's a module-level function,
not a method. The registry imports this file, finds `create_module`, calls it, and
gets back a ready-to-use `KprobeReaderModule` instance.

---

## Layer 3: JSON Serialization — `json_logger.py`

### File naming (lines 22-24)

```python
def _log_path(self) -> Path:
    today = datetime.now().strftime("%Y-%m-%d")
    return self._output_dir / f"lksm_events_{today}.jsonl"
```

Produces paths like `data/logs/lksm_events_2026-02-10.jsonl`. A new file is created
each day automatically — the path is recomputed on every write.

### Writing events (lines 30-36)

```python
def log_events(self, events: List[LKSMEvent]) -> None:
    if not events:
        return
    path = self._log_path()
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev.to_dict()) + "\n")
```

The serialization chain is:

1. `ev.to_dict()` — `dataclasses.asdict()` converts the `LKSMEvent` to a plain
   Python dict
2. `json.dumps(...)` — stdlib JSON encoder converts that dict to a JSON string
3. `+ "\n"` — one JSON object per line (JSONL format)
4. `open(path, "a")` — append mode, so events accumulate

A resulting line in the file looks like:
```json
{"seq": 0, "ts": 120.001234, "type": "kprobe_registered", "data": {"symbol": "do_init_module"}, "severity": "info", "source": "kprobe_reader"}
```

JSONL (JSON Lines) means each line is an independent, valid JSON object. This is
important because:
- The file can be read line-by-line without loading the whole thing into memory
- Appending is safe even if the process crashes mid-write (you lose at most one line)
- Tools like `jq`, `grep`, and `wc -l` work naturally on it

---

## Layer 4: The Dashboard — `dashboard.py`

### Shared state (lines 15-16)

```python
_events: deque = deque(maxlen=500)
_lock = threading.Lock()
```

These are **module-level globals** — shared between the daemon thread (which writes)
and the Flask thread (which reads). The `deque(maxlen=500)` automatically evicts the
oldest event when it's full. The `threading.Lock` prevents race conditions between
the two threads.

### Feeding events in (lines 71-75)

```python
def push_events(events: List[LKSMEvent]) -> None:
    with _lock:
        for ev in events:
            _events.append(ev.to_dict())
```

Called by the daemon loop in `main.py`. Converts each `LKSMEvent` to a dict (same
`to_dict()` call) and appends to the deque. The lock ensures the Flask thread can't
read a half-updated deque.

### Serving events out (lines 85-88)

```python
@app.route("/api/events")
def api_events():
    with _lock:
        return jsonify(list(_events))
```

`list(_events)` snapshots the deque into a plain list. `flask.jsonify()` calls
`json.dumps()` on that list of dicts and returns it with
`Content-Type: application/json`. So the browser receives:

```json
[
  {"seq": 0, "ts": 120.001234, "type": "kprobe_registered", "data": {"symbol": "do_init_module"}, "severity": "info", "source": "kprobe_reader"},
  {"seq": 1, "ts": 120.002345, "type": "suspicious_probe", "data": {"message": "SUSPICIOUS *** ..."}, "severity": "high", "source": "kprobe_reader"}
]
```

### The browser side (lines 46-64)

The inline JavaScript calls `fetch("/api/events")` every 2 seconds, parses the JSON
response, clears the table body, and rebuilds it in reverse order (newest first).
The `esc()` function prevents XSS by setting `textContent` instead of `innerHTML`
for user-controlled strings.

---

## Layer 5: Wiring It Together — `main.py`

### `run_daemon()` (lines 33-54)

```
ModuleRegistry
    -> .discover("python_tools.core.modules")   # finds kprobe_reader.py, calls create_module()
    -> .start_all(config)                        # calls kprobe_reader.start()
    loop:
        -> .poll_all()                           # calls kprobe_reader.poll(), stamps seq numbers
        -> logger.log_events(events)             # writes to .jsonl file
        -> push_events(events)                   # feeds into dashboard deque
        -> sleep(poll_interval)                  # from config, default 0.1s
```

### `run_dashboard()` (lines 57-72)

```
1. Creates a threading.Event (stop signal)
2. Starts run_daemon() in a background daemon thread
3. Creates the Flask app via create_app()
4. Runs Flask in the foreground (blocking)
5. When Flask exits (Ctrl-C), sets the stop event -> daemon thread exits
```

The daemon thread is marked `daemon=True`, which means Python will kill it
automatically when the main thread exits, even if the stop event doesn't fire
in time.

---

## The Complete Data Flow

```
Kernel: printk("[PHOTON RING] Kprobe registered for symbol: do_init_module")
    |
    v
Kernel ring buffer (in-memory, readable via dmesg)
    |
    v
kprobe_reader.poll():
    subprocess.run(["dmesg", "--decode"])  ->  raw text lines
    regex extracts timestamp + message body
    _parse_message() classifies -> (severity, type, data dict)
    constructs LKSMEvent dataclass
    |
    v
ModuleRegistry.poll_all():
    stamps monotonic seq number on each event
    |
    v
main.py daemon loop:
    |---> EventLogger.log_events():
    |        ev.to_dict()  ->  plain dict
    |        json.dumps()  ->  JSON string
    |        write to data/logs/lksm_events_2026-02-10.jsonl
    |
    +---> dashboard.push_events():
             ev.to_dict()  ->  plain dict
             append to deque (maxlen=500)
             |
             v
         Browser: fetch("/api/events") every 2s
             |
             v
         Flask: jsonify(list(deque))  ->  JSON array over HTTP
             |
             v
         JavaScript: parse JSON, rebuild HTML table
```

Every serialization step uses the same path: `LKSMEvent` -> `to_dict()`
(via `dataclasses.asdict`) -> `json.dumps()`. The dataclass is the single source of
truth for the schema. If you add a field to `LKSMEvent`, it automatically appears in
the JSONL files, the API response, and the dashboard table.

---

## Adding New printk Formats (No Python Plumbing Needed)

Any `printk` in the kernel module that includes `[PHOTON RING]` is **automatically**
picked up by the existing `kprobe_reader` module, serialized to JSONL, and displayed
on the dashboard. No new Python files, no import changes, no config changes.

For example, if you add this to the C code:

```c
printk(KERN_WARNING "[PHOTON RING] Module loaded: %s by uid %d\n", name, uid);
```

It immediately appears on the dashboard as a `photon_ring_generic` event with the
raw message in `data["message"]`. This works because the regex matches any line
containing `[PHOTON RING]`, and unrecognized formats fall through to the catch-all
branch in `_parse_message()`.

To get **structured fields** (e.g. extracting the module name and uid into separate
keys), add a branch to `_parse_message()` in
`python_tools/core/modules/kprobe_reader.py`:

```python
mod_match = re.search(r"Module loaded:\s*(\S+)\s*by uid\s*(\d+)", msg)
if mod_match:
    return "medium", "module_loaded", {
        "module": mod_match.group(1),
        "uid": int(mod_match.group(2)),
    }
```

That's it — the new fields flow through `to_dict()` -> `json.dumps()` automatically.

**Summary:** as long as the kernel module writes `[PHOTON RING]` in its `printk`
output, the Python side picks it up with zero changes. Structured parsing of new
formats is a ~3 line addition to one file (`kprobe_reader.py`).

---

## How to Add a Future Module

For entirely new data sources that are **not** dmesg-based (e.g. reading from
`/proc/lksm`, a netlink socket, or a log file):

1. Create `python_tools/core/modules/your_module.py`
2. Subclass `MonitorModule`, implement `name` / `start` / `stop` / `poll`
3. Expose a `create_module()` factory function at module level
4. Done — the registry auto-discovers it, events flow through the same logging
   and dashboard pipeline

To upgrade to `/proc/lksm` later: swap the internals of `kprobe_reader.py` from
`subprocess.run(["dmesg"])` to `open("/proc/lksm").read()`. Nothing else changes.
