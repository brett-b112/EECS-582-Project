#!/bin/bash
# LKSM Project Structure Generator
# Automatically creates the recommended directory structure

set -e

PROJECT_NAME="lksm"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "================================================"
echo "LKSM Project Structure Generator"
echo "================================================"
echo ""

# Check if project directory exists
if [ -d "$PROJECT_NAME" ]; then
    echo "WARNING: Directory '$PROJECT_NAME' already exists!"
    read -p "Continue anyway? Files will NOT be overwritten. (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo "Creating directory structure..."
echo ""

# Create main project directory
mkdir -p "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Create directory structure
echo "📁 Creating directories..."

# Root level docs
mkdir -p docs

# Kernel module
mkdir -p kernel_module/ebpf

# Python tools
mkdir -p python_tools/{core,analysis,output,config,utils}

# Configuration
mkdir -p config

# Tests
mkdir -p tests/{unit,integration,kernel}

# Scripts
mkdir -p scripts

# Data directories (git-ignored)
mkdir -p data/{logs,reports,samples}

echo "✓ Directories created"
echo ""

# Create __init__.py files for Python packages
echo "🐍 Creating Python package files..."

touch python_tools/__init__.py
touch python_tools/core/__init__.py
touch python_tools/analysis/__init__.py
touch python_tools/output/__init__.py
touch python_tools/config/__init__.py
touch python_tools/utils/__init__.py
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/integration/__init__.py

echo "✓ Python package files created"
echo ""

# Create .gitkeep for empty directories
echo "📌 Creating .gitkeep files..."

touch data/logs/.gitkeep
touch data/reports/.gitkeep
touch data/samples/.gitkeep

echo "✓ .gitkeep files created"
echo ""

# Create skeleton files
echo "📄 Creating skeleton files..."

# README.md
cat > README.md << 'EOF'
# LKSM - Linux Kernel Security Monitor

A loadable kernel module and Python toolkit for real-time Linux security monitoring.

## Quick Start

```bash
# Setup environment
bash setup.sh
source venv/bin/activate

# Build kernel module
cd kernel_module && make && cd ..

# Load kernel module
sudo scripts/load_module.sh

# Run dashboard
python -m python_tools.main --mode dashboard
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [File Structure](docs/FILE_STRUCTURE.md)
- [Dependency Management](docs/DEPENDENCY_MANAGEMENT.md)
- [Development Guide](docs/DEVELOPMENT.md)

## Project Structure

See [FILE_STRUCTURE.md](docs/FILE_STRUCTURE.md) for complete directory layout.

## Team

- Team Number: Group 32
- Team Members: TBD

## License

TBD
EOF

# Kernel module Makefile
cat > kernel_module/Makefile << 'EOF'
obj-m += lksm.o
lksm-objs := lksm_main.o lksm_hooks.o lksm_buffer.o lksm_comm.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod lksm.ko

unload:
	sudo rmmod lksm

reload: unload all load

.PHONY: all clean load unload reload
EOF

# Python main.py
cat > python_tools/main.py << 'EOF'
#!/usr/bin/env python3
"""
LKSM - Linux Kernel Security Monitor
Main entry point for Python analysis tools
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='LKSM Security Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode dashboard          Run interactive dashboard
  %(prog)s --mode daemon             Run as background daemon
  %(prog)s --mode analyze --file log.json    Analyze log file
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['daemon', 'dashboard', 'analyze'],
        default='dashboard',
        help='Operation mode (default: dashboard)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config/default_config.yml',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--file',
        type=str,
        help='Log file to analyze (for analyze mode)'
    )
    
    args = parser.parse_args()
    
    print(f"LKSM starting in {args.mode} mode...")
    print(f"Config: {args.config}")
    
    # TODO: Implement mode handlers
    if args.mode == 'dashboard':
        print("Dashboard mode not yet implemented")
    elif args.mode == 'daemon':
        print("Daemon mode not yet implemented")
    elif args.mode == 'analyze':
        if not args.file:
            print("Error: --file required for analyze mode")
            return 1
        print(f"Analyzing {args.file}...")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
EOF

chmod +x python_tools/main.py

# Default config
cat > config/default_config.yml << 'EOF'
# LKSM Default Configuration

# Communication settings
communication:
  interface: procfs  # procfs or netlink
  procfs_path: /proc/lksm
  poll_interval: 0.1  # seconds

# Logging settings
logging:
  enabled: true
  output_dir: data/logs
  format: json
  max_file_size: 100MB
  rotation: daily

# Analysis settings
analysis:
  enable_rules: true
  enable_anomaly_detection: true
  enable_network_correlation: true

# Alert settings
alerts:
  enabled: true
  syslog: true
  webhooks:
    - url: ""  # Add webhook URL
      enabled: false

# Dashboard settings
dashboard:
  refresh_rate: 1.0  # seconds
  max_events_display: 100
EOF

# Example rules
cat > config/rules.yml << 'EOF'
# LKSM Detection Rules

rules:
  - name: "Suspicious shell spawn from web server"
    description: "Web server process spawning a shell"
    type: process
    condition:
      parent_process_name:
        - nginx
        - apache2
        - httpd
      child_process_name:
        - bash
        - sh
        - zsh
    severity: high
    
  - name: "Unauthorized kernel module load"
    description: "Kernel module loaded that's not on allowlist"
    type: module
    condition:
      module_name_not_in: allowlist
    severity: critical
    
  - name: "Sensitive file access"
    description: "Access to sensitive system files"
    type: file
    condition:
      path_matches:
        - /etc/shadow
        - /etc/passwd
        - /root/.ssh/*
    severity: medium
EOF

# Load script
cat > scripts/load_module.sh << 'EOF'
#!/bin/bash
# Load LKSM kernel module

set -e

MODULE_PATH="../kernel_module/lksm.ko"

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
EOF

chmod +x scripts/load_module.sh

# Unload script
cat > scripts/unload_module.sh << 'EOF'
#!/bin/bash
# Unload LKSM kernel module

set -e

echo "Unloading LKSM kernel module..."
sudo rmmod lksm

echo "✓ Module unloaded"
EOF

chmod +x scripts/unload_module.sh

# pytest config
cat > tests/conftest.py << 'EOF'
"""
pytest configuration for LKSM tests
"""

import pytest
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def sample_event():
    """Sample event for testing"""
    return {
        'type': 'process',
        'timestamp': 1234567890,
        'pid': 1234,
        'uid': 1000,
        'process_name': 'bash',
        'parent_pid': 1000,
    }

@pytest.fixture
def config_path(tmp_path):
    """Temporary config file path"""
    config = tmp_path / "test_config.yml"
    config.write_text("# Test config\n")
    return config
EOF

echo "✓ Skeleton files created"
echo ""

# Create a basic .gitignore if it doesn't exist
if [ ! -f .gitignore ]; then
    echo "📝 Creating .gitignore..."
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
*.egg-info/
.pytest_cache/
.coverage
htmlcov/

# Kernel Module
*.o
*.ko
*.mod
*.mod.c
*.cmd
.tmp_versions/
modules.order
Module.symvers
*.markers

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Data
data/logs/*.json
data/reports/*
!data/**/.gitkeep

# Local config
config/local_*.yml
.env
EOF
    echo "✓ .gitignore created"
fi

echo ""
echo "================================================"
echo "✓ Project structure created successfully!"
echo "================================================"
echo ""
echo "Project directory: $(pwd)"
echo ""
echo "Next steps:"
echo "1. Copy dependency files:"
echo "   cp /path/to/{requirements.txt,setup.sh,Makefile,check_versions.py} ."
echo ""
echo "2. Copy documentation:"
echo "   cp /path/to/{DEPENDENCY_MANAGEMENT.md,KERNEL_DEPENDENCIES.md,FILE_STRUCTURE.md} docs/"
echo ""
echo "3. Run setup:"
echo "   bash setup.sh"
echo ""
echo "4. Start developing!"
echo ""

# Print directory tree
echo "Directory structure:"
echo ""
tree -L 2 -I 'venv|__pycache__|*.pyc' || find . -maxdepth 2 -type d | grep -v '^\./\.' | sort
echo ""
