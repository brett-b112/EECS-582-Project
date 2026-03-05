# Makefile for Photon Ring kernel module

# Module name
MODULE_NAME := photon_ring

# Object files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o modules/kprobe_detector.o modules/hooking_audit_detector.o modules/taskstats_hook_detector.o modules/tcp_hiding_detector.o modules/become_root_detector.o modules/bpf_hook_detector.o modules/hiding_stat.o modules/hook_file_access.o

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Build directory
PWD := $(shell pwd)

# Compiler flags - add include path
ccflags-y := -Wall -Wextra -I$(PWD)/include

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f modules/*.o modules/.*.cmd modules/*.mod.c modules/.*.d
	rm -f *.o .*.cmd *.mod.c .*.d

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

# Reload target (uninstall, clean, build, install)
reload: uninstall clean all install

# Status target
status:
	@echo "Module status:"
	@lsmod | grep -E "^Module|$(MODULE_NAME)" || echo "Module not loaded"
	@echo ""
	@echo "Module file:"
	@ls -lh $(MODULE_NAME).ko 2>/dev/null || echo "Module not built"

# Help target
help:
	@echo "Photon Ring Kernel Module Build System"
	@echo "======================================="
	@echo "Current structure:"
	@echo "  main.c"
	@echo "  include/kprobe_detector.h"
	@echo "  modules/kprobe_detector.c"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the kernel module (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Build and install the module"
	@echo "  uninstall  - Remove the module from kernel"
	@echo "  reload     - Uninstall, clean, rebuild, and install"
	@echo "  status     - Show module load status"
	@echo "  logs       - Show recent kernel logs"
	@echo "  clearlogs  - Clear kernel ring buffer"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build module"
	@echo "  make install      # Install module"
	@echo "  make logs         # View logs"
	@echo "  make reload       # Quick reload for testing"
	@echo "  make uninstall    # Remove module"

.PHONY: all clean install uninstall logs clearlogs reload status help