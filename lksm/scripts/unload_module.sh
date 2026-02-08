#!/bin/bash
# Unload LKSM kernel module

set -e

echo "Unloading LKSM kernel module..."
sudo rmmod lksm

echo "✓ Module unloaded"
