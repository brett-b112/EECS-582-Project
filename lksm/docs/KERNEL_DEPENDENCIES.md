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

## Version Requirements

- Kernel: 5.10+
- GCC: 9.0+
- Python: 3.8+ (for python_tools)
