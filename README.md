# LKSM - Linux Kernel Security Monitor

A loadable kernel module and Python toolkit for real-time Linux security monitoring.

## Overview

LKSM has two intertwined components:

1. **Kernel Module** (C) — a loadable kernel module (`lksm.ko`) that hooks into the Linux kernel to monitor security events in real-time (syscalls, network activity, etc.)
2. **Python Tools** — a user-space Python suite that reads data from the kernel module (via `/proc/lksm`), analyzes it, and displays it in a dashboard or logs it

The Python tools consume data produced by the kernel module. The kernel module must be loaded first, then the Python tools connect to it to display and analyze the monitoring data.

**Prerequisite:** This must be run on a **Linux machine** (Ubuntu/Debian/Fedora/Arch). It requires Linux kernel headers and kernel module loading.

## Quick Start

### Step 1: Environment Setup

```bash
cd lksm
bash setup.sh
```

This installs system packages (gcc, make, kernel headers, Python, etc.), verifies kernel config has required features enabled, creates a Python virtual environment, and installs all Python dependencies.

### Step 2: Activate the Virtual Environment

```bash
source venv/bin/activate
```

You need to do this every time you open a new terminal.

### Step 3: Verify Everything

```bash
python check_versions.py
make test-env
```

`check_versions.py` checks Python version (3.8–3.12), GCC (9+), kernel version (4.15+), kernel headers, virtual env status, and that all Python packages match `requirements.txt`.

`make test-env` does a similar environment check via the Makefile.

### Step 4: Build the Kernel Module

```bash
cd kernel_module && make && cd ..
```

This compiles the kernel module (`lksm.ko`) from four source files: `lksm_main.c`, `lksm_hooks.c`, `lksm_buffer.c`, `lksm_comm.c`.

### Step 5: Load the Kernel Module

```bash
sudo scripts/load_module.sh
```

Verify it's loaded with:

```bash
lsmod | grep lksm
dmesg | tail
```

### Step 6: Run the Python Monitoring Tools

```bash
python -m python_tools.main --mode dashboard    # Interactive dashboard
python -m python_tools.main --mode daemon        # Background monitoring
python -m python_tools.main --mode analyze --file log.json  # Analyze a log file
```

### Stopping / Unloading

```bash
sudo scripts/unload_module.sh
```

## Version Checks

| Method | Command | What it checks |
|--------|---------|----------------|
| Python script | `python check_versions.py` | Python version, venv active, GCC version, kernel version, kernel headers, Python package versions |
| Makefile | `make test-env` | venv exists, gcc/make/python3 installed, kernel headers found, lists installed pip packages |
| Makefile | `make verify-kernel` | Checks specific kernel config options (CONFIG_MODULES, CONFIG_KPROBES, etc.) |

## Documentation

- [Architecture](lksm/docs/Architecture/LKSM_Architecture_Document.pdf)
- [Dependency Management](lksm/docs/DEPENDENCY_MANAGEMENT.md)
- [Kernel Dependencies](lksm/docs/KERNEL_DEPENDENCIES.md)
- [Quick Reference](lksm/docs/QUICK_START.md)

## Team

- Team Number: Group 32
- Team Members: Jamie King, Brett Balquist, Kaden Huber, Hart Nurnber, Max Biundo, & Dustin Le

## License

MIT
