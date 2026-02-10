# LKSM Quick Start Guide

## Prerequisites

- Linux with kernel headers installed
- `build-essential` (gcc, make)
- Python 3.8+

## 1. Clone and Set Up

```bash
git clone <your-repo-url>
cd lksm

# Install system deps and set up Python venv
bash setup.sh

# Activate the Python environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## 2. Build the Kernel Module

```bash
cd kernel_module
make
```

This produces `kprobe_detector.ko`.

## 3. Load the Module

```bash
sudo insmod kprobe_detector.ko
```

Verify it loaded:

```bash
lsmod | grep kprobe_detector
sudo dmesg | tail -5
```

You should see:

```
[PHOTON RING] initializing kprobe detector...
[PHOTON RING] successfully hooked register_kprobe
[PHOTON RING] now monitoring all kprobe registrations...
```

## 4. Run the Dashboard

The monitoring dashboard reads `[PHOTON RING]` events from dmesg and displays
them in a live web UI.

**Important:** The dashboard needs permission to read the kernel ring buffer
(`dmesg`). Modern kernels restrict this to root by default. You have two options:

**Option A — Run the dashboard with sudo** (recommended):

```bash
sudo venv/bin/python -m python_tools.main --mode dashboard
```

Note: `sudo python` won't find the venv Python — you must use the full
`venv/bin/python` path.

**Option B — Allow your user to read dmesg** (persists until reboot):

```bash
sudo sysctl kernel.dmesg_restrict=0
python -m python_tools.main --mode dashboard
```

Then open **http://127.0.0.1:5000** in your browser. The event table
auto-refreshes every 2 seconds.

### Other Modes

```bash
# Headless daemon — polls modules and writes JSON logs only (no web UI)
sudo venv/bin/python -m python_tools.main --mode daemon

# Use a custom config file
sudo venv/bin/python -m python_tools.main --mode dashboard --config path/to/config.yml
```

Events are also logged to `data/logs/lksm_events_YYYY-MM-DD.jsonl`.

## 5. Run Tests

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

## 6. Unload the Module

```bash
sudo rmmod kprobe_detector
```

## Extending the Kernel Module

Any `printk` in the kernel module that includes `[PHOTON RING]` is automatically
picked up by the Python pipeline — logged to JSONL and shown on the dashboard —
with **no Python changes required**. For example, if you add a new printk on the
C side:

```c
printk(KERN_WARNING "[PHOTON RING] Module loaded: %s by uid %d\n", name, uid);
```

It will appear on the dashboard immediately as a generic event
(`type: "photon_ring_generic"`) with the raw message in the details column.

To get **structured parsing** (extracting the module name and uid into separate
fields), add a branch to `_parse_message()` in
`python_tools/core/modules/kprobe_reader.py`. That's a ~3 line change in one file.

For entirely new data sources (not dmesg-based), create a new module file in
`python_tools/core/modules/`. See `docs/notes/python_pipeline_deep_dive.md` for
the full walkthrough.

## Rebuilding After Changes

```bash
cd kernel_module
make clean
make
```

## Troubleshooting

### No events on the dashboard

The most common cause is `dmesg` permission. Test it:

```bash
dmesg | grep "PHOTON RING"
```

If you see `Operation not permitted`, either run the dashboard with
`sudo venv/bin/python` or relax the restriction:

```bash
sudo sysctl kernel.dmesg_restrict=0
```

### `sudo python`: command not found

`sudo` does not inherit your virtual environment. Always use the full path:

```bash
sudo venv/bin/python -m python_tools.main --mode dashboard
```

### "insmod: ERROR: could not insert module ... Invalid parameters"

Your kernel may not support the ftrace flags the module uses. Check the kernel
config:

```bash
grep DYNAMIC_FTRACE /boot/config-$(uname -r)
```

The module requires `CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y` (ARM64) or
`CONFIG_DYNAMIC_FTRACE_WITH_REGS=y` (x86). Most stock Ubuntu/Debian kernels
have this enabled.

### "kernel headers not found"

```bash
sudo apt install linux-headers-$(uname -r)
```

### Verify kernel configuration

```bash
make verify-kernel
```

This checks that `CONFIG_MODULES`, `CONFIG_KPROBES`, `CONFIG_DYNAMIC_FTRACE`,
and `CONFIG_TRACEPOINTS` are enabled.
