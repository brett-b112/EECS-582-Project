#!/bin/bash
# Unload the kprobe_detector kernel module

set -e

echo "Unloading kprobe_detector kernel module..."
sudo rmmod kprobe_detector

echo "Module unloaded. Check dmesg for confirmation:"
echo "  sudo dmesg | tail -5"
