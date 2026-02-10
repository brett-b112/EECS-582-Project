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

## 4. Monitor

Watch for kprobe registration events in real-time:

```bash
sudo dmesg -w
```

## 5. Unload the Module

```bash
sudo rmmod kprobe_detector
```

## Rebuilding After Changes

```bash
cd kernel_module
make clean
make
```

## Troubleshooting

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
