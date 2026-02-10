#!/bin/bash
# Load LKSM kernel module

set -e

MODULE_PATH="../kernel_module/kprobe_detector.ko"

if [ ! -f "$MODULE_PATH" ]; then
    echo "Error: Module not found at $MODULE_PATH"
    echo "Build it first with: cd kernel_module && make"
    exit 1
fi

echo "Loading LKSM kernel module..."
sudo insmod "$MODULE_PATH" debug=1

echo "✓ Module loaded"
echo ""
echo "Verify with: lsmod | grep lksm"
echo "View logs with: dmesg | tail"
