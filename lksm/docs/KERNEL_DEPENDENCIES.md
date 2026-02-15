# Kernel Dependencies

## Required Packages

### Debian/Ubuntu

```bash
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    kmod
```

### Fedora/RHEL

```bash
sudo dnf install -y \
    kernel-devel \
    kernel-headers \
    gcc \
    make
```

## Required Kernel Config Options

The running kernel must have these enabled (most stock distro kernels do):

```
CONFIG_MODULES=y
CONFIG_KPROBES=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_TRACEPOINTS=y
```

Additionally, the module needs one of these for ftrace argument access:

- `CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y` (ARM64, kernel 6.x+)
- `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y` (x86_64)

Check your config:

```bash
grep -E 'CONFIG_MODULES|CONFIG_KPROBES|DYNAMIC_FTRACE' /boot/config-$(uname -r)
```

## dmesg Access

The Python monitoring tools read kernel events from the ring buffer via
`dmesg`. On most modern kernels, `kernel.dmesg_restrict` defaults to `1`,
meaning only root can read dmesg.

Check the current setting:

```bash
sysctl kernel.dmesg_restrict
```

If it is `1`, you have two options when running the dashboard or daemon:

1. **Run with sudo** using the venv Python path:
   ```bash
   sudo venv/bin/python -m python_tools.main --mode dashboard
   ```

2. **Relax the restriction** (reverts on reboot):
   ```bash
   sudo sysctl kernel.dmesg_restrict=0
   ```

## Version Requirements

- Kernel: 5.10+
- GCC: 9.0+
- Python: 3.8+ (for python_tools)
