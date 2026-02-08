# LKSM Project File Structure

This document defines the recommended directory structure for the Linux Kernel Security Monitor project.

## 📁 Complete Directory Tree

```
lksm/
├── README.md                          # Project overview and quick start
├── LICENSE                            # Project license
├── .gitignore                         # Git ignore rules
├── requirements.txt                   # Python dependencies (pinned versions)
├── setup.sh                          # Automated environment setup script
├── Makefile                          # Build and environment management commands
├── check_versions.py                 # Environment verification script
│
├── docs/                             # Documentation
│   ├── DEPENDENCY_MANAGEMENT.md      # Dependency guide
│   ├── KERNEL_DEPENDENCIES.md        # System package requirements
│   ├── ARCHITECTURE.md               # Architecture documentation
│   ├── API.md                        # API documentation
│   ├── DEVELOPMENT.md                # Development guidelines
│   ├── TESTING.md                    # Testing strategy
│   └── DEPLOYMENT.md                 # Deployment instructions
│
├── kernel_module/                    # Kernel space component (C)
│   ├── Makefile                      # Kernel module build file
│   ├── lksm_main.c                   # Main module entry point
│   ├── lksm_hooks.c                  # Hook implementations
│   ├── lksm_hooks.h                  # Hook headers
│   ├── lksm_buffer.c                 # Ring buffer implementation
│   ├── lksm_buffer.h                 # Buffer headers
│   ├── lksm_comm.c                   # Communication layer (procfs/netlink)
│   ├── lksm_comm.h                   # Communication headers
│   ├── lksm_types.h                  # Shared type definitions
│   ├── lksm_config.h                 # Module configuration
│   └── ebpf/                         # eBPF-related code (optional)
│       ├── syscall_filter.c
│       └── syscall_filter.h
│
├── python_tools/                     # User space component (Python)
│   ├── __init__.py                   # Package initialization
│   ├── main.py                       # Main entry point / CLI
│   │
│   ├── core/                         # Core functionality
│   │   ├── __init__.py
│   │   ├── event_reader.py           # Reads events from kernel
│   │   ├── log_parser.py             # Parses and structures events
│   │   ├── event_types.py            # Event data classes/types
│   │   └── comm_channel.py           # Communication channel handler
│   │
│   ├── analysis/                     # Analysis components
│   │   ├── __init__.py
│   │   ├── rule_engine.py            # Rule-based detection
│   │   ├── anomaly_detector.py       # Behavioral analysis
│   │   ├── network_correlator.py     # Network event correlation
│   │   └── forensic_timeline.py      # Timeline reconstruction
│   │
│   ├── output/                       # Output and alerting
│   │   ├── __init__.py
│   │   ├── logger.py                 # JSON log writer
│   │   ├── alert_system.py           # Alert dispatcher
│   │   ├── dashboard.py              # Real-time terminal dashboard
│   │   └── reporter.py               # Report generation
│   │
│   ├── config/                       # Configuration management
│   │   ├── __init__.py
│   │   ├── config_loader.py          # YAML config loader
│   │   └── validator.py              # Config validation
│   │
│   └── utils/                        # Utility functions
│       ├── __init__.py
│       ├── helpers.py                # General helpers
│       └── constants.py              # Constants and enums
│
├── config/                           # Configuration files
│   ├── default_config.yml            # Default configuration
│   ├── rules.yml                     # Detection rules
│   ├── allowlist.yml                 # Allowed processes/files
│   ├── denylist.yml                  # Denied processes/files
│   └── alerts.yml                    # Alert configuration
│
├── tests/                            # Test suite
│   ├── __init__.py
│   ├── conftest.py                   # Pytest configuration
│   │
│   ├── unit/                         # Unit tests
│   │   ├── __init__.py
│   │   ├── test_event_reader.py
│   │   ├── test_log_parser.py
│   │   ├── test_rule_engine.py
│   │   ├── test_anomaly_detector.py
│   │   └── test_alert_system.py
│   │
│   ├── integration/                  # Integration tests
│   │   ├── __init__.py
│   │   ├── test_kernel_communication.py
│   │   ├── test_end_to_end.py
│   │   └── test_pipeline.py
│   │
│   └── kernel/                       # Kernel module tests
│       ├── test_module_load.sh       # Test module loading
│       ├── test_hooks.sh             # Test hook functionality
│       └── test_communication.sh     # Test kernel-user comm
│
├── scripts/                          # Utility scripts
│   ├── load_module.sh                # Load kernel module with params
│   ├── unload_module.sh              # Safely unload module
│   ├── generate_test_events.sh       # Generate test events
│   ├── analyze_logs.sh               # Quick log analysis
│   └── demo.sh                       # Demo script for presentation
│
├── data/                             # Data directory (git-ignored)
│   ├── logs/                         # JSON event logs
│   │   └── .gitkeep
│   ├── reports/                      # Generated reports
│   │   └── .gitkeep
│   └── samples/                      # Sample data for testing
│       └── .gitkeep
│
└── venv/                             # Python virtual environment (git-ignored)
```

## 📋 File Organization Principles

### 1. **Separation of Concerns**
- **kernel_module/** - All C code for kernel space
- **python_tools/** - All Python code for user space
- **config/** - Configuration files (YAML)
- **tests/** - All test code
- **docs/** - All documentation

### 2. **Logical Grouping**
Python tools are organized by function:
- **core/** - Event reading and parsing
- **analysis/** - Detection and correlation
- **output/** - Logging, alerts, dashboards
- **config/** - Configuration management
- **utils/** - Shared utilities

### 3. **Clear Dependencies**
```
kernel_module → (procfs/netlink) → python_tools/core → python_tools/analysis → python_tools/output
```

## 🗂️ Key Directories Explained

### `/kernel_module/`
Contains all kernel-space C code. Each component has separate `.c` and `.h` files:
- **lksm_main.c** - Module initialization, cleanup
- **lksm_hooks.c** - Process, file, network, module hooks
- **lksm_buffer.c** - Ring buffer for event queuing
- **lksm_comm.c** - procfs/netlink communication

**Why separate files?** Easier to develop, test, and debug individual components.

### `/python_tools/`
Organized as a proper Python package with subpackages:
- **core/** - Low-level event handling
- **analysis/** - High-level intelligence
- **output/** - All output mechanisms
- **config/** - Configuration loading

**Why subpackages?** Clean imports, clear boundaries, easier testing.

### `/config/`
YAML configuration files:
- **default_config.yml** - System defaults
- **rules.yml** - Detection rules (e.g., "alert if nginx spawns bash")
- **allowlist.yml** - Known-good processes
- **denylist.yml** - Known-bad processes
- **alerts.yml** - Alert destinations (webhook URLs, syslog config)

**Why separate configs?** Different team members can work on different aspects.

### `/tests/`
Mirrors the structure of the code:
- **unit/** - Test individual functions/classes
- **integration/** - Test component interactions
- **kernel/** - Bash scripts to test kernel module

**Why mirror structure?** Easy to find tests for each component.

### `/scripts/`
Operational scripts:
- **load_module.sh** - `sudo insmod lksm.ko debug=1`
- **unload_module.sh** - `sudo rmmod lksm`
- **generate_test_events.sh** - Creates test events
- **demo.sh** - Automated demo for presentation

### `/data/`
Runtime data (git-ignored):
- **logs/** - JSON event logs
- **reports/** - Generated reports
- **samples/** - Test data

## 🏗️ Component Mapping to Files

### From Architecture Document:

| Component | File(s) |
|-----------|---------|
| **Process Hook** | `kernel_module/lksm_hooks.c::process_hook_*()` |
| **File Hook** | `kernel_module/lksm_hooks.c::file_hook_*()` |
| **Network Hook** | `kernel_module/lksm_hooks.c::network_hook_*()` |
| **Module Hook** | `kernel_module/lksm_hooks.c::module_hook_*()` |
| **Event Buffer** | `kernel_module/lksm_buffer.c` |
| **/proc/lksm** | `kernel_module/lksm_comm.c::procfs_*()` |
| **Event Reader** | `python_tools/core/event_reader.py` |
| **Log Parser** | `python_tools/core/log_parser.py` |
| **Rule Engine** | `python_tools/analysis/rule_engine.py` |
| **Anomaly Detector** | `python_tools/analysis/anomaly_detector.py` |
| **Network Correlator** | `python_tools/analysis/network_correlator.py` |
| **Dashboard** | `python_tools/output/dashboard.py` |
| **Alert System** | `python_tools/output/alert_system.py` |
| **JSON Logs** | `python_tools/output/logger.py` → `data/logs/` |
| **Forensic Timeline** | `python_tools/analysis/forensic_timeline.py` |

## 📦 Python Package Structure

The `python_tools/` directory is a proper Python package:

```python
# python_tools/__init__.py
"""LKSM Python Analysis Tools"""
__version__ = "0.1.0"

from .core import event_reader, log_parser
from .analysis import rule_engine, anomaly_detector
from .output import dashboard, alert_system

# python_tools/main.py
#!/usr/bin/env python3
"""Main entry point for LKSM tools"""
import argparse
from python_tools.core.event_reader import EventReader
from python_tools.output.dashboard import Dashboard

def main():
    parser = argparse.ArgumentParser(description='LKSM Security Monitor')
    parser.add_argument('--mode', choices=['daemon', 'dashboard', 'analyze'])
    args = parser.parse_args()
    
    if args.mode == 'dashboard':
        dashboard = Dashboard()
        dashboard.run()
    # ...

if __name__ == '__main__':
    main()
```

**Usage:**
```bash
# Run as module
python -m python_tools.main --mode dashboard

# Or install in development mode
pip install -e .
lksm --mode dashboard
```

## 🔧 Build and Run Structure

### Kernel Module
```bash
cd kernel_module/
make                    # Builds lksm.ko
sudo insmod lksm.ko     # Loads module
dmesg | tail           # Check kernel logs
sudo rmmod lksm         # Unloads module
```

### Python Tools
```bash
source venv/bin/activate
cd python_tools/
python main.py --mode dashboard
```

## 📝 Configuration File Locations

### Development
```
config/default_config.yml    # Checked into git
config/rules.yml             # Checked into git
```

### Production/Local Overrides
```
config/local_config.yml      # Git-ignored, overrides defaults
config/local_rules.yml       # Git-ignored, custom rules
```

**Pattern:** Default configs in git, local overrides git-ignored.

## 🧪 Test Organization

```
tests/
├── unit/                    # Fast, isolated tests
│   └── test_rule_engine.py  # Tests rule_engine.py logic
├── integration/             # Multi-component tests
│   └── test_pipeline.py     # Tests event flow end-to-end
└── kernel/                  # Kernel module tests
    └── test_hooks.sh        # Loads module, generates events, checks output
```

**Run tests:**
```bash
pytest tests/unit/                    # Fast unit tests
pytest tests/integration/             # Slower integration tests
bash tests/kernel/test_hooks.sh       # Kernel tests (needs sudo)
```

## 📚 Documentation Structure

```
docs/
├── ARCHITECTURE.md          # System design (from PDF)
├── DEVELOPMENT.md           # How to contribute
├── API.md                   # Python API reference
├── TESTING.md               # Testing strategy
└── DEPLOYMENT.md            # How to deploy/run
```

**Auto-generated docs:**
```bash
cd docs/
sphinx-apidoc -o api ../python_tools
make html
# Opens docs/_build/html/index.html
```

## 🎯 Best Practices

### DO:
✅ Keep kernel code in `kernel_module/`
✅ Keep Python code in `python_tools/`
✅ Put configs in `config/`
✅ Mirror test structure to code structure
✅ Use `__init__.py` for package initialization
✅ Keep scripts in `scripts/`
✅ Git-ignore `venv/`, `data/`, `*.ko`, `*.o`

### DON'T:
❌ Mix kernel and Python code in same directory
❌ Put config files in code directories
❌ Commit logs or data files
❌ Commit virtual environment
❌ Put tests in same files as code

## 🚀 Getting Started with This Structure

```bash
# 1. Create directory structure
mkdir -p lksm/{kernel_module,python_tools/{core,analysis,output,config,utils},config,tests/{unit,integration,kernel},scripts,data/{logs,reports,samples},docs}

# 2. Create __init__.py files
touch lksm/python_tools/{__init__.py,core/__init__.py,analysis/__init__.py,output/__init__.py,config/__init__.py,utils/__init__.py}
touch lksm/tests/{__init__.py,unit/__init__.py,integration/__init__.py}

# 3. Create .gitkeep for empty directories
touch lksm/data/{logs,reports,samples}/.gitkeep

# 4. Copy dependency files
cp requirements.txt setup.sh Makefile .gitignore lksm/

# 5. Initialize git
cd lksm/
git init
git add .
git commit -m "Initial project structure"
```

## 📊 File Count by Sprint

Based on the 6-sprint plan:

**Sprint 1-2:** Setup + Process/File Hooks
- kernel_module/: 6 files
- python_tools/core/: 4 files
- config/: 2 files

**Sprint 3:** Network/Module Hooks
- kernel_module/: +2 files
- python_tools/core/: +1 file

**Sprint 4:** Python Tools + Dashboard
- python_tools/analysis/: 4 files
- python_tools/output/: 4 files

**Sprint 5:** Alerts + Reports
- python_tools/output/: +1 file
- config/: +2 files

**Sprint 6:** Testing + Docs
- tests/: 10+ files
- docs/: 5+ files

**Total: ~50 source files** by project end.

## 🔄 Workflow Example

**Developer working on anomaly detector:**

```bash
# 1. Activate environment
source venv/bin/activate

# 2. Navigate to component
cd python_tools/analysis/

# 3. Edit code
vim anomaly_detector.py

# 4. Run unit tests
pytest ../../tests/unit/test_anomaly_detector.py

# 5. Run integration tests
pytest ../../tests/integration/

# 6. Test with real kernel module
cd ../../
sudo python -m python_tools.main --mode daemon

# 7. Commit
git add python_tools/analysis/anomaly_detector.py
git commit -m "Implement frequency-based anomaly detection"
```

---

This structure supports the team working in parallel on different components while maintaining clean separation and easy integration.
