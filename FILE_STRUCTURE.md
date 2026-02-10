# LKSM Project File Structure

This document defines the directory structure for the Linux Kernel Security Monitor project.

## Complete Directory Tree

```
lksm/
├── requirements.txt                   # Python dependencies (pinned versions)
├── setup.sh                          # Automated environment setup script
├── Makefile                          # Build and environment management commands
├── check_versions.py                 # Environment verification script
│
├── docs/                             # Documentation
│   ├── QUICK_START.md                # Quick start guide
│   ├── KERNEL_DEPENDENCIES.md        # System package requirements
│   ├── DEPENDENCY_MANAGEMENT.md      # Dependency guide
│   └── Architecture/
│       ├── LKSM_Architecture_Document.pdf
│       └── architecture.mermaid
│
├── kernel_module/                    # Kernel space component (C)
│   ├── Makefile                      # Kernel module build file
│   ├── photon_ring_arch.h            # Arch translation layer (x86/ARM64)
│   └── kprobe_detector.c             # Kprobe registration monitor
│
├── python_tools/                     # User space component (Python)
│   ├── __init__.py                   # Package initialization
│   ├── main.py                       # Main entry point / CLI
│   │
│   ├── core/                         # Core functionality
│   │   └── __init__.py
│   │
│   ├── analysis/                     # Analysis components
│   │   └── __init__.py
│   │
│   ├── output/                       # Output and alerting
│   │   └── __init__.py
│   │
│   ├── config/                       # Configuration management
│   │   └── __init__.py
│   │
│   └── utils/                        # Utility functions
│       └── __init__.py
│
├── config/                           # Configuration files
│   ├── default_config.yml            # Default configuration
│   └── rules.yml                     # Detection rules
│
├── tests/                            # Test suite
│   ├── __init__.py
│   ├── conftest.py                   # Pytest configuration
│   │
│   ├── unit/                         # Unit tests
│   │   └── __init__.py
│   │
│   └── integration/                  # Integration tests
│       └── __init__.py
│
├── scripts/                          # Utility scripts
│   ├── load_module.sh                # Build and load kernel module
│   └── unload_module.sh              # Unload module and clean build
│
├── data/                             # Data directory (git-ignored)
│   ├── reports/                      # Generated reports
│   │   └── .gitkeep
│   └── samples/                      # Sample data for testing
│       └── .gitkeep
│
└── venv/                             # Python virtual environment (git-ignored)
```

## File Organization Principles

### 1. **Separation of Concerns**
- **kernel_module/** - All C code for kernel space
- **python_tools/** - All Python code for user space
- **config/** - Configuration files (YAML)
- **tests/** - All test code
- **docs/** - All documentation

### 2. **Clear Dependencies**
```
kernel_module → (procfs/netlink) → python_tools/core → python_tools/analysis → python_tools/output
```

## Key Directories Explained

### `/kernel_module/`
Contains all kernel-space C code:
- **photon_ring_arch.h** - Architecture translation macros for portable ftrace access across x86_64 and ARM64
- **kprobe_detector.c** - Monitors kprobe registrations via ftrace to detect suspicious hooks (e.g., rootkits probing `kallsyms_lookup_name`)

### `/python_tools/`
Organized as a proper Python package with subpackages:
- **core/** - Low-level event handling
- **analysis/** - High-level intelligence
- **output/** - All output mechanisms
- **config/** - Configuration loading

### `/config/`
YAML configuration files:
- **default_config.yml** - System defaults
- **rules.yml** - Detection rules

### `/tests/`
- **unit/** - Test individual functions/classes
- **integration/** - Test component interactions

### `/scripts/`
Operational scripts:
- **load_module.sh** - Builds and loads `kprobe_detector.ko`, shows status and logs
- **unload_module.sh** - Unloads module and runs `make clean`

### `/data/`
Runtime data (git-ignored):
- **reports/** - Generated reports
- **samples/** - Test data

## Build and Run

### Kernel Module
```bash
cd kernel_module/
make                              # Builds kprobe_detector.ko
sudo insmod kprobe_detector.ko    # Loads module
sudo dmesg | grep 'PHOTON RING'  # Check kernel logs
sudo rmmod kprobe_detector        # Unloads module
```

Or use the scripts:
```bash
bash scripts/load_module.sh       # Build + load + show status
bash scripts/unload_module.sh     # Unload + clean
```

### Python Tools
```bash
source venv/bin/activate
python -m python_tools.main
```

## Verification

```bash
python check_versions.py     # Check Python, GCC, kernel
make test-env                # Check venv, tools, headers
make verify-kernel           # Check kernel config options
```

## Best Practices

### DO:
- Keep kernel code in `kernel_module/`
- Keep Python code in `python_tools/`
- Put configs in `config/`
- Mirror test structure to code structure
- Use `__init__.py` for package initialization
- Keep scripts in `scripts/`
- Git-ignore `venv/`, `data/`, `*.ko`, `*.o`

### DON'T:
- Mix kernel and Python code in same directory
- Put config files in code directories
- Commit logs or data files
- Commit virtual environment
- Put tests in same files as code

---

This structure supports the team working in parallel on different components while maintaining clean separation and easy integration.
