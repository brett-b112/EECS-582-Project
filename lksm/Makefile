# LKSM Project Makefile
# Helps manage environment setup and testing

.PHONY: help setup test-env clean-venv verify-kernel install-dev

# Default target
help:
	@echo "LKSM Development Environment Management"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@echo "  setup          - Run the environment setup script"
	@echo "  test-env       - Verify environment is correctly configured"
	@echo "  verify-kernel  - Check kernel configuration"
	@echo "  install-dev    - Install development dependencies"
	@echo "  clean-venv     - Remove Python virtual environment"
	@echo "  freeze         - Generate current Python dependency versions"
	@echo "  help           - Show this help message"
	@echo ""

# Run the setup script
setup:
	@bash setup.sh

# Test environment configuration
test-env:
	@echo "Testing environment configuration..."
	@echo "===================================="
	@echo ""
	@echo "Python Environment:"
	@if [ -d "venv" ]; then \
		echo "  ✓ Virtual environment exists"; \
	else \
		echo "  ✗ Virtual environment not found (run 'make setup')"; \
		exit 1; \
	fi
	@echo ""
	@echo "System Tools:"
	@command -v gcc >/dev/null 2>&1 && echo "  ✓ gcc found: $$(gcc --version | head -n1)" || echo "  ✗ gcc not found"
	@command -v make >/dev/null 2>&1 && echo "  ✓ make found: $$(make --version | head -n1)" || echo "  ✗ make not found"
	@command -v python3 >/dev/null 2>&1 && echo "  ✓ python3 found: $$(python3 --version)" || echo "  ✗ python3 not found"
	@echo ""
	@echo "Kernel Headers:"
	@if [ -d "/lib/modules/$$(uname -r)/build" ]; then \
		echo "  ✓ Kernel headers found for $$(uname -r)"; \
	else \
		echo "  ✗ Kernel headers not found for $$(uname -r)"; \
	fi
	@echo ""
	@echo "Python Dependencies:"
	@if [ -f "venv/bin/activate" ]; then \
		. venv/bin/activate && pip list | head -n10; \
	else \
		echo "  ✗ Virtual environment not activated"; \
	fi
	@echo ""

# Verify kernel configuration
verify-kernel:
	@echo "Verifying kernel configuration..."
	@echo "=================================="
	@echo ""
	@echo "Kernel Version: $$(uname -r)"
	@echo ""
	@if [ -f /boot/config-$$(uname -r) ]; then \
		echo "Checking required kernel options:"; \
		for opt in CONFIG_MODULES CONFIG_KPROBES CONFIG_DYNAMIC_FTRACE CONFIG_TRACEPOINTS; do \
			if grep -q "^$$opt=y" /boot/config-$$(uname -r); then \
				echo "  ✓ $$opt"; \
			else \
				echo "  ✗ $$opt (NOT ENABLED)"; \
			fi; \
		done; \
		echo ""; \
		echo "Ftrace argument access (need at least one):"; \
		if grep -q "^CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y" /boot/config-$$(uname -r); then \
			echo "  ✓ CONFIG_DYNAMIC_FTRACE_WITH_ARGS (ARM64)"; \
		else \
			echo "  - CONFIG_DYNAMIC_FTRACE_WITH_ARGS not set"; \
		fi; \
		if grep -q "^CONFIG_DYNAMIC_FTRACE_WITH_REGS=y" /boot/config-$$(uname -r); then \
			echo "  ✓ CONFIG_DYNAMIC_FTRACE_WITH_REGS (x86)"; \
		else \
			echo "  - CONFIG_DYNAMIC_FTRACE_WITH_REGS not set"; \
		fi; \
	else \
		echo "  ? Kernel config not found at /boot/config-$$(uname -r)"; \
	fi
	@echo ""

# Install development dependencies
install-dev:
	@if [ ! -d "venv" ]; then \
		echo "Virtual environment not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@. venv/bin/activate && pip install -r requirements.txt
	@echo "✓ Development dependencies installed"

# Clean virtual environment
clean-venv:
	@echo "Removing virtual environment..."
	@rm -rf venv
	@echo "✓ Virtual environment removed"

# Freeze current dependencies
freeze:
	@if [ ! -d "venv" ]; then \
		echo "Virtual environment not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@. venv/bin/activate && pip freeze > requirements-frozen.txt
	@echo "✓ Current dependencies saved to requirements-frozen.txt"
	@echo ""
	@echo "To share this with the team:"
	@echo "  1. Review requirements-frozen.txt"
	@echo "  2. Update requirements.txt if needed"
	@echo "  3. Commit both files to git"
