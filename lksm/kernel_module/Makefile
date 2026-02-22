# Makefile for Photon Ring kernel module

# Module name
MODULE_NAME := photon_ring

# Object files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o modules/kprobe_detector.o comms/event_manager.o comms/crypto.o comms/netlink_ch.o

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Build directory
PWD := $(shell pwd)

# Compiler flags
ccflags-y := -Wall -Wextra -I$(PWD)/include

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Install target
install: all
	sudo insmod $(MODULE_NAME).ko

# Uninstall target
uninstall:
	sudo rmmod $(MODULE_NAME)

# Show kernel logs
logs:
	sudo dmesg | tail -50

# Clear kernel logs
clearlogs:
	sudo dmesg -c > /dev/null

# Help target
help:
	@echo "Photon Ring Kernel Module Build System"
	@echo "======================================="
	@echo "Targets:"
	@echo "  all        - Build the kernel module (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Build and install the module"
	@echo "  uninstall  - Remove the module from kernel"
	@echo "  logs       - Show recent kernel logs"
	@echo "  clearlogs  - Clear kernel ring buffer"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build module"
	@echo "  make install      # Install module"
	@echo "  make logs         # View logs"
	@echo "  make uninstall    # Remove module"

.PHONY: all clean install uninstall logs clearlogs help