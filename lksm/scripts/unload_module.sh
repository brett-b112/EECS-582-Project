#!/bin/bash
# Unload the kprobe_detector kernel module and clean build artifacts

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR="$SCRIPT_DIR/../kernel_module"

if ! lsmod | grep -q kprobe_detector; then
    echo "kprobe_detector module is not loaded."
else
    echo "=== Unloading Module ==="
    sudo rmmod kprobe_detector

    echo ""
    echo "=== Kernel Logs ==="
    sudo dmesg | grep 'PHOTON RING' | tail -5 || true
fi

echo ""
echo "=== Cleaning Build ==="
make -C "$MODULE_DIR" clean
