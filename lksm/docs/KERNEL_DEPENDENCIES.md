# LKSM - Kernel Module Dependencies
# System Requirements for Building and Running the LKM

## Required Packages (Debian/Ubuntu)
build-essential         # GCC, make, and essential build tools
linux-headers-$(uname -r)  # Kernel headers matching your running kernel
kmod                   # Tools for managing kernel modules (modprobe, insmod, etc.)
gcc                    # GNU C Compiler (typically 9.0+)
make                   # Build automation tool
libc6-dev              # C standard library development files

## Optional but Recommended
linux-source           # Full kernel source (for advanced kprobes work)
libelf-dev             # ELF library (needed for eBPF compilation)
llvm                   # LLVM compiler infrastructure (for eBPF)
clang                  # C language frontend for LLVM (for eBPF)
libbpf-dev             # BPF library development files

## Debugging and Testing Tools
gdb                    # GNU debugger
crash                  # Kernel crash analysis tool
systemtap              # System-wide profiling/tracing
strace                 # System call tracer
dmesg                  # Kernel ring buffer viewer

## Kernel Configuration Requirements
The target kernel must have these options enabled:
CONFIG_MODULES=y
CONFIG_KPROBES=y
CONFIG_TRACEPOINTS=y
CONFIG_PROC_FS=y
CONFIG_NETLINK=y
CONFIG_DEBUG_INFO=y      # Recommended for debugging
CONFIG_BPF=y             # Required for eBPF features
CONFIG_BPF_SYSCALL=y     # Required for eBPF features

## Version Requirements
Minimum Kernel Version: 4.15
Recommended: 5.10+ (for better eBPF support)
GCC Version: 9.0+
Python Version: 3.8+

## Installing on Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    kmod \
    gcc \
    make \
    libc6-dev \
    libelf-dev \
    llvm \
    clang \
    libbpf-dev

## Installing on RHEL/CentOS/Fedora
sudo dnf install -y \
    kernel-devel \
    kernel-headers \
    gcc \
    make \
    elfutils-libelf-devel \
    llvm \
    clang \
    libbpf-devel

## Installing on Arch Linux
sudo pacman -Syu \
    base-devel \
    linux-headers \
    gcc \
    make \
    libelf \
    llvm \
    clang \
    libbpf
