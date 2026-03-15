# Makefile for Photon Ring kernel module + userspace agent

# ─────────────────────────────────────────────────────────────────────────────
# Kernel module
# ─────────────────────────────────────────────────────────────────────────────

MODULE_NAME := photon_ring

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o modules/kprobe_detector.o modules/become_root_detector.o modules/bpf_hook_detector.o modules/tcp_hiding_detector.o comms/event_manager.o comms/crypto.o comms/cdev_ch.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Flags used by the kernel build system for module sources
ccflags-y := -Wall -Wextra -I$(PWD)/include

# ─────────────────────────────────────────────────────────────────────────────
# Userspace agent
# ─────────────────────────────────────────────────────────────────────────────

AGENT_SRC  := photon_agent.c
AGENT_BIN  := photon_agent
AGENT_CC   := gcc
AGENT_CFLAGS := -O2 -Wall -Wextra -std=c11 \
                -I$(PWD)/include
AGENT_LIBS := -lssl -lcrypto

# ─────────────────────────────────────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────────────────────────────────────

# Default: build everything
all: module agent

# Build only the kernel module
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build only the userspace agent
agent: $(AGENT_SRC)
	$(AGENT_CC) $(AGENT_CFLAGS) -o $(AGENT_BIN) $(AGENT_SRC) $(AGENT_LIBS)
	@echo "[PHOTON RING] Agent built: $(AGENT_BIN)"

# Clean all build artifacts (module + agent)
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(AGENT_BIN)

# Install: load module and copy agent to /usr/local/bin
install: all
	sudo insmod $(MODULE_NAME).ko
	sudo install -m 0750 -o root -g root $(AGENT_BIN) /usr/local/bin/$(AGENT_BIN)

# Uninstall: remove module and agent binary
uninstall:
	sudo rmmod $(MODULE_NAME)
	sudo rm -f /usr/local/bin/$(AGENT_BIN)

# Show recent kernel logs
logs:
	sudo dmesg | tail -50

# Clear kernel ring buffer
clearlogs:
	sudo dmesg -c > /dev/null

# Help
help:
	@echo "Photon Ring Build System"
	@echo "========================"
	@echo "Targets:"
	@echo "  all        - Build kernel module + userspace agent (default)"
	@echo "  module     - Build kernel module only"
	@echo "  agent      - Build userspace agent only"
	@echo "  clean      - Remove all build artifacts"
	@echo "  install    - Build, load module, install agent to /usr/local/bin"
	@echo "  uninstall  - Unload module, remove installed agent"
	@echo "  logs       - Show recent kernel logs (last 50 lines)"
	@echo "  clearlogs  - Clear kernel ring buffer"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR       - Kernel build directory (default: /lib/modules/\$$(uname -r)/build)"
	@echo "  AGENT_CC   - C compiler for agent (default: gcc)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make                        # Build everything"
	@echo "  make module                 # Kernel module only"
	@echo "  make agent                  # Agent only"
	@echo "  make install                # Load module + install agent"
	@echo "  make KDIR=/path/to/kernel   # Custom kernel source"

.PHONY: all module agent clean install uninstall logs clearlogs help