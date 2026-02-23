# PHOTON RING
<img width="500" height="500" alt="photon_ring_logo" src="https://github.com/user-attachments/assets/4c139850-ec36-4381-98c4-fa9b5222bb18" />

A kernel module that detects rootkit-style activity (kprobe hooking, audit evasion, taskstats manipulation) and a web dashboard that displays detections in real time.

## Project Structure

```
lksm/
├── kernel_module/          # The kernel module (C)
│   ├── Makefile
│   ├── main.c              # Entry point, loads all detectors
│   ├── include/             # Header files
│   └── modules/             # Detector implementations
│       ├── kprobe_detector.c
│       ├── hooking_audit_detector.c
│       └── taskstats_hook_detector.c
├── python_tools/           # Dashboard and event reader (Python)
│   ├── main.py             # CLI entry point
│   ├── core/               # Event parsing from dmesg
│   └── output/             # Flask web dashboard + JSON logger
├── config/                 # Default configuration files
├── data/logs/              # Event logs (created at runtime)
└── requirements.txt        # Python dependencies
```

## Prerequisites

- Ubuntu/Debian Linux
- Python 3.8+

Install the required system packages:

```bash
sudo apt install build-essential linux-headers-$(uname -r) python3-venv
```

## Setup

```bash
cd lksm

# Create a Python virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Building and Loading the Kernel Module

```bash
cd lksm/kernel_module

# Build
make

# Load the module
sudo insmod photon_ring.ko

# Verify it loaded
lsmod | grep photon_ring
sudo dmesg | "PHOTON RING"
```

You should see output like:

```
[PHOTON RING] Initializing detection system
[PHOTON RING] Starting detector: kprobe_detector
[PHOTON RING] successfully hooked register_kprobe
[PHOTON RING] All detectors active (3/3)
[PHOTON RING] System is now monitoring...
```

### Other Makefile Commands

| Command          | What it does                          |
|------------------|---------------------------------------|
| `make`           | Build the module                      |
| `make clean`     | Remove build artifacts                |
| `make install`   | Build and load the module             |
| `make uninstall` | Unload the module                     |
| `make reload`    | Unload, clean, rebuild, and reload    |
| `make logs`      | Show recent kernel logs               |
| `make status`    | Check if the module is loaded         |

## Running the Dashboard

The dashboard reads `[PHOTON RING]` messages from dmesg and shows them in a live web page.

From the `lksm/` directory:

```bash
sudo venv/bin/python -m python_tools.main --mode dashboard
```

Then open **http://127.0.0.1:5000** in your browser.

> **Why sudo?** Modern kernels restrict `dmesg` to root. You must use the full
> `venv/bin/python` path because `sudo` does not inherit your virtual environment.

### Headless Mode (no web UI, just logging)

```bash
sudo venv/bin/python -m python_tools.main --mode daemon
```

Events are logged to `data/logs/lksm_events_YYYY-MM-DD.jsonl`.

## Unloading the Module

```bash
sudo rmmod photon_ring
```

## Troubleshooting

**No events on the dashboard** - Make sure the kernel module is loaded and you ran the dashboard with `sudo`.

**"insmod: ERROR: could not insert module ... Invalid parameters"** - Your kernel may be missing ftrace support. Check with:

```bash
grep DYNAMIC_FTRACE /boot/config-$(uname -r)
```

You need `CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y` (ARM64) or `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y` (x86).

**"kernel headers not found" during make** - Install them:

```bash
sudo apt install linux-headers-$(uname -r)
```

## How It Works

1. The kernel module hooks into kernel functions using ftrace and logs suspicious activity via `printk` to the kernel ring buffer (dmesg).
2. The Python dashboard polls `dmesg` for `[PHOTON RING]` messages, parses them into structured events, and serves them through a Flask web UI that auto-refreshes every 2 seconds.

### Current Detectors

- **kprobe_detector** - Monitors kprobe registrations. Flags suspicious probes (e.g. `kallsyms_lookup_name`).
- **taskstats_hook_detector** - Monitors taskstats, generic netlink, and process connector hooks.
- **hooking_audit_detector** - Monitors audit subsystem hooks (netlink_unicast, audit_log_*, syscall audit).

## Team

- Team Number: Group 32
- Team Members: Jamie King, Brett Balquist, Kaden Huber, Hart Nurnberg, Max Biundo, & Dustin Le

## License

MIT
