#!/bin/bash
# Build and load the kprobe detector kernel module

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR="$SCRIPT_DIR/../kernel_module"
MODULE_PATH="$MODULE_DIR/kprobe_detector.ko"

echo "=== Building Module ==="
make -C "$MODULE_DIR"

echo ""
echo "=== Loading Module ==="
sudo insmod "$MODULE_PATH"

echo ""
echo "=== Module Status ==="
lsmod | grep kprobe_detector || true

echo ""
echo "=== Kernel Logs ==="
sudo dmesg | grep 'PHOTON RING' || true
