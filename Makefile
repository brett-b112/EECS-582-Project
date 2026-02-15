MODULE_NAME := photon_ring

# object files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o kprobe_detector.o event_manager.o crypto_layer.o netlink_channel.o

# kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Build directory
PWD := $(shell pwd)

# compiler flags
ccflags-y := -Wall -Wextra

# default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo insmod $(MODULE_NAME).ko

uninstall:
	sudo rmmod $(MODULE_NAME)

# show kernel logs
logs:
	sudo dmesg | tail -50

# Clear kernel logs
clearlogs:
	sudo dmesg -c > /dev/null

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