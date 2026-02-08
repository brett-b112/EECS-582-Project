# LKSM Project Directory Tree

## Visual Structure

```
lksm/
│
├── 📄 README.md                          # Project overview
├── 📄 LICENSE                            # License file
├── 📄 .gitignore                         # Git ignore rules
├── 📄 requirements.txt                   # Python dependencies (PINNED)
├── 📄 setup.sh                          # Environment setup script
├── 📄 Makefile                          # Build & test commands
├── 📄 check_versions.py                 # Verify environment
│
├── 📁 docs/                             # 📚 DOCUMENTATION
│   ├── ARCHITECTURE.md                   # System design
│   ├── FILE_STRUCTURE.md                 # This structure guide
│   ├── DEPENDENCY_MANAGEMENT.md          # Dependency guide
│   ├── DEVELOPMENT.md                    # Dev guidelines
│   ├── TESTING.md                        # Testing strategy
│   └── DEPLOYMENT.md                     # Deployment guide
│
├── 📁 kernel_module/                    # 🔧 KERNEL SPACE (C)
│   ├── Makefile                          # Build kernel module
│   ├── lksm_main.c                       # Module entry/exit
│   ├── lksm_hooks.c                      # Hook implementations
│   ├── lksm_hooks.h                      # Hook headers
│   ├── lksm_buffer.c                     # Ring buffer
│   ├── lksm_buffer.h                     # Buffer headers
│   ├── lksm_comm.c                       # Communication layer
│   ├── lksm_comm.h                       # Comm headers
│   ├── lksm_types.h                      # Type definitions
│   ├── lksm_config.h                     # Module config
│   └── ebpf/                             # eBPF support (optional)
│       ├── syscall_filter.c
│       └── syscall_filter.h
│
├── 📁 python_tools/                     # 🐍 USER SPACE (Python)
│   ├── __init__.py                       # Package init
│   ├── main.py                           # Entry point / CLI
│   │
│   ├── core/                             # Core functionality
│   │   ├── __init__.py
│   │   ├── event_reader.py               # Read from kernel
│   │   ├── log_parser.py                 # Parse events
│   │   ├── event_types.py                # Event data types
│   │   └── comm_channel.py               # procfs/netlink handler
│   │
│   ├── analysis/                         # Analysis engine
│   │   ├── __init__.py
│   │   ├── rule_engine.py                # Rule-based detection
│   │   ├── anomaly_detector.py           # Behavioral analysis
│   │   ├── network_correlator.py         # Network correlation
│   │   └── forensic_timeline.py          # Timeline reconstruction
│   │
│   ├── output/                           # Output & alerting
│   │   ├── __init__.py
│   │   ├── logger.py                     # JSON logger
│   │   ├── alert_system.py               # Alert dispatcher
│   │   ├── dashboard.py                  # Terminal dashboard
│   │   └── reporter.py                   # Report generator
│   │
│   ├── config/                           # Config management
│   │   ├── __init__.py
│   │   ├── config_loader.py              # YAML loader
│   │   └── validator.py                  # Config validator
│   │
│   └── utils/                            # Utilities
│       ├── __init__.py
│       ├── helpers.py                    # Helper functions
│       └── constants.py                  # Constants
│
├── 📁 config/                           # ⚙️ CONFIGURATION
│   ├── default_config.yml                # Default settings
│   ├── rules.yml                         # Detection rules
│   ├── allowlist.yml                     # Allowed items
│   ├── denylist.yml                      # Blocked items
│   └── alerts.yml                        # Alert config
│
├── 📁 tests/                            # 🧪 TESTS
│   ├── __init__.py
│   ├── conftest.py                       # pytest config
│   │
│   ├── unit/                             # Unit tests
│   │   ├── __init__.py
│   │   ├── test_event_reader.py
│   │   ├── test_log_parser.py
│   │   ├── test_rule_engine.py
│   │   ├── test_anomaly_detector.py
│   │   └── test_alert_system.py
│   │
│   ├── integration/                      # Integration tests
│   │   ├── __init__.py
│   │   ├── test_kernel_communication.py
│   │   ├── test_end_to_end.py
│   │   └── test_pipeline.py
│   │
│   └── kernel/                           # Kernel tests
│       ├── test_module_load.sh
│       ├── test_hooks.sh
│       └── test_communication.sh
│
├── 📁 scripts/                          # 🔨 UTILITY SCRIPTS
│   ├── load_module.sh                    # Load kernel module
│   ├── unload_module.sh                  # Unload module
│   ├── generate_test_events.sh           # Generate test data
│   ├── analyze_logs.sh                   # Quick analysis
│   └── demo.sh                           # Demo script
│
├── 📁 data/                             # 💾 DATA (git-ignored)
│   ├── logs/                             # JSON event logs
│   │   └── .gitkeep
│   ├── reports/                          # Generated reports
│   │   └── .gitkeep
│   └── samples/                          # Sample data
│       └── .gitkeep
│
└── 📁 venv/                             # 🐍 Virtual env (git-ignored)
```

## Component Organization

### By Development Phase

**Sprint 1-2: Foundation**
```
kernel_module/
├── lksm_main.c        ← Sprint 1
├── lksm_buffer.c      ← Sprint 1
├── lksm_comm.c        ← Sprint 1
└── lksm_hooks.c       ← Sprint 2 (process + file)

python_tools/core/
├── event_reader.py    ← Sprint 2
└── log_parser.py      ← Sprint 2
```

**Sprint 3: Extended Hooks**
```
kernel_module/
└── lksm_hooks.c       ← Add network + module hooks

python_tools/core/
└── comm_channel.py    ← Enhanced communication
```

**Sprint 4: Analysis**
```
python_tools/analysis/
├── rule_engine.py         ← Sprint 4
├── anomaly_detector.py    ← Sprint 4
└── network_correlator.py  ← Sprint 4

python_tools/output/
└── dashboard.py           ← Sprint 4
```

**Sprint 5: Output**
```
python_tools/output/
├── alert_system.py    ← Sprint 5
├── reporter.py        ← Sprint 5
└── logger.py          ← Sprint 5

config/
├── alerts.yml         ← Sprint 5
└── rules.yml          ← Sprint 5
```

**Sprint 6: Polish**
```
tests/                 ← Sprint 6
docs/                  ← Sprint 6
scripts/               ← Sprint 6
```

### By Ownership (for team collaboration)

**Person A: Kernel Development**
```
kernel_module/
├── lksm_main.c
├── lksm_hooks.c
├── lksm_buffer.c
└── lksm_comm.c
```

**Person B: Event Processing**
```
python_tools/core/
├── event_reader.py
├── log_parser.py
└── comm_channel.py
```

**Person C: Analysis & Detection**
```
python_tools/analysis/
├── rule_engine.py
├── anomaly_detector.py
└── network_correlator.py
```

**Person D: Output & UI**
```
python_tools/output/
├── dashboard.py
├── alert_system.py
└── reporter.py
```

**Everyone: Configuration & Testing**
```
config/        ← Shared
tests/         ← Everyone writes tests for their code
docs/          ← Everyone documents their components
```

## File Size Estimates

```
Component               Files    Estimated LOC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
kernel_module/          10       ~1,500-2,000
python_tools/core/      5        ~800-1,000
python_tools/analysis/  4        ~1,200-1,500
python_tools/output/    4        ~1,000-1,200
python_tools/config/    2        ~300-400
python_tools/utils/     2        ~200-300
tests/                  15+      ~1,500-2,000
config/                 5        ~200 (YAML)
scripts/                5        ~500
docs/                   7        ~3,000 (Markdown)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOTAL                   ~60      ~10,000-12,000
```

## Quick Navigation Guide

**Want to:**
- Build kernel module? → `kernel_module/Makefile`
- Run the system? → `python_tools/main.py`
- Add detection rule? → `config/rules.yml`
- View logs? → `data/logs/`
- Run tests? → `pytest tests/`
- Load module? → `scripts/load_module.sh`
- Check environment? → `check_versions.py`
- Read docs? → `docs/`

## Integration Points

```
┌─────────────────┐
│ kernel_module/  │
│  lksm_comm.c    │─────┐
└─────────────────┘     │ /proc/lksm
                        │ or netlink
┌─────────────────┐     │
│ python_tools/   │◄────┘
│  core/          │
│   event_reader  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ python_tools/   │
│  analysis/      │
│   rule_engine   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ python_tools/   │
│  output/        │
│   alert_system  │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ data/logs/      │
│ Syslog          │
│ Webhooks        │
└─────────────────┘
```

## Key Principles

1. **Separation**: Kernel ≠ Python ≠ Tests ≠ Config
2. **Modularity**: Each component in its own file
3. **Clarity**: Names match architecture document
4. **Testability**: Mirror structure in tests/
5. **Documentation**: Match structure in docs/

---

Generated for LKSM Group 32
