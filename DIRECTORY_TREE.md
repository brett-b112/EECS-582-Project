# LKSM Project Directory Tree

## Visual Structure

```
lksm/
│
├── 📄 requirements.txt                   # Python dependencies (PINNED)
├── 📄 setup.sh                          # Environment setup script
├── 📄 Makefile                          # Build & test commands
├── 📄 check_versions.py                 # Verify environment
│
├── 📁 docs/                             # 📚 DOCUMENTATION
│   ├── QUICK_START.md                    # Quick start guide
│   ├── KERNEL_DEPENDENCIES.md            # System package requirements
│   ├── DEPENDENCY_MANAGEMENT.md          # Dependency guide
│   └── Architecture/
│       ├── LKSM_Architecture_Document.pdf
│       └── architecture.mermaid
│
├── 📁 kernel_module/                    # 🔧 KERNEL SPACE (C)
│   ├── Makefile                          # Build kernel module (photon_ring.ko)
│   ├── main.c                            # Detector registry & module entry point
│   ├── photon_ring_arch.h                # Arch translation layer (x86/ARM64)
│   ├── include/
│   │   └── kprobe_detector.h             # Kprobe detector header
│   └── modules/
│       └── kprobe_detector.c             # Kprobe registration monitor
│
├── 📁 python_tools/                     # 🐍 USER SPACE (Python)
│   ├── __init__.py                       # Package init
│   ├── main.py                           # Entry point / CLI
│   │
│   ├── core/                             # Core functionality
│   │   └── __init__.py
│   │
│   ├── analysis/                         # Analysis engine
│   │   └── __init__.py
│   │
│   ├── output/                           # Output & alerting
│   │   └── __init__.py
│   │
│   ├── config/                           # Config management
│   │   └── __init__.py
│   │
│   └── utils/                            # Utilities
│       └── __init__.py
│
├── 📁 config/                           # ⚙️ CONFIGURATION
│   ├── default_config.yml                # Default settings
│   └── rules.yml                         # Detection rules
│
├── 📁 tests/                            # 🧪 TESTS
│   ├── __init__.py
│   ├── conftest.py                       # pytest config
│   │
│   ├── unit/                             # Unit tests
│   │   └── __init__.py
│   │
│   └── integration/                      # Integration tests
│       └── __init__.py
│
├── 📁 scripts/                          # 🔨 UTILITY SCRIPTS
│   ├── load_module.sh                    # Build and load kernel module
│   └── unload_module.sh                  # Unload module and clean build
│
└── 📁 venv/                             # 🐍 Virtual env (git-ignored)
```

## Quick Navigation Guide

**Want to:**
- Build kernel module? → `kernel_module/Makefile`
- Run the system? → `python_tools/main.py`
- Add detection rule? → `config/rules.yml`
- Run tests? → `pytest tests/`
- Load module? → `scripts/load_module.sh`
- Check environment? → `check_versions.py`
- Read docs? → `docs/`

## Key Principles

1. **Separation**: Kernel ≠ Python ≠ Tests ≠ Config
2. **Modularity**: Each component in its own file
3. **Clarity**: Names match architecture document
4. **Testability**: Mirror structure in tests/
5. **Documentation**: Match structure in docs/

---

Generated for LKSM Group 32
