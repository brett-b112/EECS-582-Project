#!/bin/bash
# LKSM Development Environment Setup Script
# This script ensures all team members have consistent dependencies

set -e  # Exit on error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR"

echo "================================================"
echo "LKSM Development Environment Setup"
echo "================================================"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Check if running as root for system packages
if [ "$EUID" -eq 0 ]; then 
    echo "WARNING: Don't run this script as root. It will use sudo when needed."
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Install system dependencies for kernel module development
echo "Step 1: Installing kernel development dependencies..."
echo "------------------------------------------------------"

case $OS in
    ubuntu|debian)
        echo "Installing packages for Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            linux-headers-$(uname -r) \
            kmod \
            gcc \
            make \
            libc6-dev \
            libelf-dev \
            python3 \
            python3-pip \
            python3-venv \
            git
        
        # Optional: eBPF support
        read -p "Install eBPF dependencies? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get install -y llvm clang libbpf-dev
        fi
        ;;
    
    fedora|rhel|centos)
        echo "Installing packages for RHEL/CentOS/Fedora..."
        sudo dnf install -y \
            kernel-devel \
            kernel-headers \
            gcc \
            make \
            elfutils-libelf-devel \
            python3 \
            python3-pip \
            git
        
        # Optional: eBPF support
        read -p "Install eBPF dependencies? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo dnf install -y llvm clang libbpf-devel
        fi
        ;;
    
    arch|manjaro)
        echo "Installing packages for Arch Linux..."
        sudo pacman -Syu --needed \
            base-devel \
            linux-headers \
            gcc \
            make \
            libelf \
            python \
            python-pip \
            git
        
        # Optional: eBPF support
        read -p "Install eBPF dependencies? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo pacman -S --needed llvm clang libbpf
        fi
        ;;
    
    *)
        echo "Unsupported OS: $OS"
        echo "Please install dependencies manually. See KERNEL_DEPENDENCIES.md"
        exit 1
        ;;
esac

echo ""
echo "✓ System dependencies installed"
echo ""

# Step 2: Verify kernel configuration
echo "Step 2: Verifying kernel configuration..."
echo "------------------------------------------------------"

check_kernel_config() {
    local config=$1
    if [ -f /boot/config-$(uname -r) ]; then
        if grep -q "^$config=y" /boot/config-$(uname -r); then
            echo "  ✓ $config is enabled"
            return 0
        else
            echo "  ✗ $config is NOT enabled"
            return 1
        fi
    else
        echo "  ? Cannot verify $config (config file not found)"
        return 2
    fi
}

CONFIGS_OK=true
check_kernel_config "CONFIG_MODULES" || CONFIGS_OK=false
check_kernel_config "CONFIG_KPROBES" || CONFIGS_OK=false
check_kernel_config "CONFIG_DYNAMIC_FTRACE" || CONFIGS_OK=false
check_kernel_config "CONFIG_TRACEPOINTS" || CONFIGS_OK=false

# Check for ftrace argument access (need at least one)
if [ -f /boot/config-$(uname -r) ]; then
    if grep -q "^CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y" /boot/config-$(uname -r); then
        echo "  ✓ CONFIG_DYNAMIC_FTRACE_WITH_ARGS is enabled (ARM64 ftrace)"
    elif grep -q "^CONFIG_DYNAMIC_FTRACE_WITH_REGS=y" /boot/config-$(uname -r); then
        echo "  ✓ CONFIG_DYNAMIC_FTRACE_WITH_REGS is enabled (x86 ftrace)"
    else
        echo "  ✗ Neither CONFIG_DYNAMIC_FTRACE_WITH_ARGS nor CONFIG_DYNAMIC_FTRACE_WITH_REGS is enabled"
        CONFIGS_OK=false
    fi
fi

if [ "$CONFIGS_OK" = false ]; then
    echo ""
    echo "WARNING: Some required kernel features are not enabled."
    echo "The kernel module may not work correctly."
    echo ""
fi

echo ""

# Step 3: Set up Python virtual environment
echo "Step 3: Setting up Python virtual environment..."
echo "------------------------------------------------------"

VENV_DIR="$PROJECT_ROOT/venv"

if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists at $VENV_DIR"
    read -p "Recreate it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
    fi
else
    python3 -m venv "$VENV_DIR"
fi

echo "✓ Virtual environment created"
echo ""

# Step 4: Install Python dependencies
echo "Step 4: Installing Python dependencies..."
echo "------------------------------------------------------"

source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip

# Install dependencies from requirements.txt
if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    pip install -r "$PROJECT_ROOT/requirements.txt"
    echo "✓ Python dependencies installed"
else
    echo "WARNING: requirements.txt not found. Skipping Python dependencies."
fi

echo ""

# Step 5: Verify installation
echo "Step 5: Verifying installation..."
echo "------------------------------------------------------"

echo "Kernel version: $(uname -r)"
echo "GCC version: $(gcc --version | head -n1)"
echo "Python version: $(python3 --version)"
echo "Make version: $(make --version | head -n1)"

if command_exists pytest; then
    echo "pytest version: $(pytest --version | head -n1)"
fi

# Step 6: Build kernel module
echo "Step 6: Building kernel module..."
echo "------------------------------------------------------"

if [ -f "$PROJECT_ROOT/kernel_module/Makefile" ]; then
    make -C "$PROJECT_ROOT/kernel_module" clean 2>/dev/null || true
    make -C "$PROJECT_ROOT/kernel_module"
    echo "✓ Kernel module built: kernel_module/kprobe_detector.ko"
else
    echo "WARNING: kernel_module/Makefile not found. Skipping build."
fi

echo ""
echo "================================================"
echo "Setup Complete!"
echo "================================================"
echo ""
echo "To activate the Python environment:"
echo "  source venv/bin/activate"
echo ""
echo "To load the kernel module:"
echo "  sudo insmod kernel_module/kprobe_detector.ko"
echo ""
echo "To unload:"
echo "  sudo rmmod kprobe_detector"
echo ""
echo "To watch detections (raw):"
echo "  sudo dmesg -w"
echo ""
echo "To run the web dashboard (http://127.0.0.1:5000):"
echo "  sudo venv/bin/python -m python_tools.main --mode dashboard"
echo ""
echo "NOTE: The dashboard reads dmesg, which requires root."
echo "Use 'sudo venv/bin/python' (not 'sudo python') so sudo"
echo "can find the virtual-environment Python."
echo ""
echo "To run tests:"
echo "  source venv/bin/activate"
echo "  python -m pytest tests/ -v"
echo ""
