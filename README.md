# PHOTON RING
<img width="500" height="500" alt="photon_ring_logo" src="https://github.com/user-attachments/assets/4c139850-ec36-4381-98c4-fa9b5222bb18" />

A kernel module that detects rootkit-style activity (kprobe hooking, audit evasion, taskstats manipulation, privilege escalation, BPF/TCP/ICMP hook detection, taint clearing, PID/file/directory hiding, ftrace tampering, and LKRG bypass attempts). Detections are severity-classified and delivered through an encrypted kernel-to-userspace pipeline (AES-256-GCM over a character device, relayed by a TLS 1.3 agent to a remote server) or via a dmesg fallback path, then indexed into Elasticsearch for real-time visualization in Kibana.

## Project Structure

```
lksm/
├── docker-compose.yml           # Elasticsearch + Kibana stack
├── kernel_module/               # The kernel module (C)
│   ├── Makefile
│   ├── main.c                   # Entry point, detector registry, init/exit lifecycle
│   ├── photon_agent.c           # Userspace TLS 1.3 agent (key exchange + frame relay)
│   ├── include/                 # Header files (per-detector .h + infrastructure)
│   │   ├── photon_ring_arch.h   # Portable argument extraction (x86_64 / ARM64)
│   │   ├── event_manager.h      # Event structs, severity levels, payload types
│   │   ├── crypto.h             # AES-256-GCM encryption interface
│   │   ├── cdev_ch.h            # Character device interface
│   │   └── watchlists.h         # 39 critical kernel symbols
│   ├── comms/                   # Encrypted communication pipeline
│   │   ├── event_manager.c      # Per-CPU ring buffers, severity classification
│   │   ├── crypto.c             # AES-256-GCM encryption, HKDF-SHA256 key derivation
│   │   └── cdev_ch.c            # /dev/photon_ring character device, ring buffer, ioctl
│   └── modules/                 # Detector implementations (20 .c files)
│       ├── kprobe_detector.c
│       ├── kretprobe_detector.c
│       ├── kallsyms_detector.c
│       ├── ftrace_direct_detector.c
│       ├── become_root_detector.c
│       ├── bpf_hook_detector.c
│       ├── tcp_hiding_detector.c
│       ├── icmp_hook_detector.c
│       ├── reset_tainted_detector.c
│       ├── clear_taint_dmesg_detector.c
│       ├── trace_pid_detector.c
│       ├── hiding_stat.c
│       ├── hiding_directory.c
│       ├── hiding_chdir_detector.c
│       ├── hiding_readlink_detector.c
│       ├── hooks_write_detector.c
│       ├── hook_file_access.c
│       ├── lkrg_bypass_detector.c
│       ├── hooking_audit_detector.c
│       └── taskstats_hook_detector.c
├── python_tools/                # Event processing and ES indexing (Python)
│   ├── main.py                  # CLI entry point (daemon / dashboard modes)
│   ├── server.py                # Remote TLS server (key distribution, frame decryption, ES indexing)
│   ├── core/                    # Event parsing from dmesg
│   │   └── modules/
│   │       └── dmesg_reader.py  # Regex-based event parser with severity classification
│   └── output/                  # Elasticsearch writer + JSON logger
│       ├── es_writer.py         # Bulk ES indexer
│       └── json_logger.py       # Daily JSONL file logger
├── arch/
│   └── architecture.mermaid     # System architecture diagram
├── scripts/
│   └── setup_kibana.py          # One-time Kibana data view setup
├── config/                      # Default configuration files
│   ├── default_config.yml       # Main config (ES, polling, logging)
│   └── rules.yml                # Detection rule definitions
├── es_payload_structure.md      # Elasticsearch document schema reference
├── data/logs/                   # Event logs (created at runtime)
└── requirements.txt             # Python dependencies
```

## Prerequisites 
## MUST BE INSTALLED ON YOUR MACHINE

- Ubuntu/Debian Linux
- Python 3.8+
- Docker and Docker Compose

Install the required system packages:

```bash
sudo apt install build-essential linux-headers-$(uname -r) libssl-dev python3-venv docker docker-compose
```

## Setup

### 1. Python Environment

```bash
cd lksm

# Create a Python virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Start Elasticsearch and Kibana

From the `lksm/` directory:

```bash
sudo docker-compose up -d
```

This starts two containers:

| Service | Port | Description |
|---------|------|-------------|
| Elasticsearch | `localhost:9200` | Event storage and search engine |
| Kibana | `localhost:5601` | Web-based visualization dashboard |

Kibana will wait for Elasticsearch to be healthy before starting. You can verify Elasticsearch is ready with:

```bash
sudo docker-compose ps
```

### 3. Create the Kibana Data View (one-time)

```bash
python scripts/setup_kibana.py
```

This script waits for Kibana to become available, then creates an **"LKSM Events"** data view pointed at the `lksm_events` index. You only need to run this once.

### 4. Build and Load the Kernel Module

```bash
cd lksm/kernel_module

# Build
make

# Load the module
sudo insmod photon_ring.ko

# Verify it loaded
lsmod | grep photon_ring
sudo dmesg | tail -30
```

You should see output like:

```
[PHOTON RING] Initializing detection system
[PHOTON RING] Starting detector: kprobe_detector
[PHOTON RING] successfully hooked register_kprobe
[PHOTON RING] All detectors active (4/4)
[PHOTON RING] System is now monitoring...
```

#### Makefile Commands

| Command          | What it does                                       |
|------------------|----------------------------------------------------|
| `make`           | Build kernel module + userspace agent (default)    |
| `make module`    | Build only the kernel module                       |
| `make agent`     | Build only the userspace agent                     |
| `make clean`     | Remove all build artifacts                         |
| `make install`   | Build, load module, install agent to /usr/local/bin|
| `make uninstall` | Unload module, remove installed agent              |
| `make logs`      | Show recent kernel logs (last 50 lines)            |
| `make clearlogs` | Clear kernel ring buffer                           |
| `make help`      | Show all targets and variables                     |

### 5. Run the Python Daemon

From the `lksm/` directory:

```bash
# Dashboard mode (directs you to Kibana, then runs the daemon):
sudo venv/bin/python -m python_tools.main --mode dashboard

# Headless mode (no UI, just logging + ES indexing):
sudo venv/bin/python -m python_tools.main --mode daemon
```

> **Why sudo?** Modern kernels restrict `dmesg` to root. You must use the full
> `venv/bin/python` path because `sudo` does not inherit your virtual environment.

The daemon polls dmesg for `[PHOTON RING]` messages, parses them into structured events, and:
- Writes them to `data/logs/lksm_events_YYYY-MM-DD.jsonl`
- Indexes them into Elasticsearch via the bulk API

### 6. View Detections in Kibana

Open **http://localhost:5601** in your browser, go to **Discover**, and select the **"LKSM Events"** data view. Events will appear in real time as the kernel module detects suspicious activity.

## Teardown

```bash
# Unload the kernel module
sudo rmmod photon_ring

# Stop Elasticsearch and Kibana
cd lksm
sudo docker-compose down

# To also delete stored event data:
sudo docker-compose down -v
```

## Configuration

Configuration is in `lksm/config/default_config.yml`. Key settings:

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `elasticsearch` | `enabled` | `true` | Enable/disable ES indexing |
| `elasticsearch` | `host` | `http://localhost:9200` | Elasticsearch endpoint |
| `elasticsearch` | `index` | `lksm_events` | Index name for events |
| `communication` | `poll_interval` | `0.1` | Seconds between dmesg polls |
| `logging` | `enabled` | `true` | Enable JSONL file logging |
| `logging` | `output_dir` | `data/logs` | Directory for log files |

## Troubleshooting

**No events in Kibana** — Make sure the kernel module is loaded (`lsmod | grep photon_ring`), the daemon is running with `sudo`, and Elasticsearch is healthy (`curl http://localhost:9200`).

**Kibana not loading** — Wait a minute after `sudo docker-compose up -d`. Kibana takes time to initialize. Check container status with `sudo docker-compose ps`.

**"insmod: ERROR: could not insert module ... Invalid parameters"** — Your kernel may be missing ftrace support. Check with:

```bash
grep DYNAMIC_FTRACE /boot/config-$(uname -r)
```

You need `CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y` (ARM64) or `CONFIG_DYNAMIC_FTRACE_WITH_REGS=y` (x86).

**"kernel headers not found" during make** — Install them:

```bash
sudo apt install linux-headers-$(uname -r)
```

## How It Works

Photon Ring delivers detections to Elasticsearch through two independent data paths:

### Primary Path — Encrypted Kernel Channel

1. The **kernel module** uses ftrace, kprobes, and tracepoints to hook into kernel functions across 20 detectors. When suspicious activity is detected, a structured `photon_event` is created with severity classification (`INFO`, `SUSPICIOUS`, `ALERT`, `CRITICAL`).
2. The **event manager** (`comms/event_manager.c`) enqueues events into per-CPU ring buffers (256 slots each) with atomic sequence numbering for gap detection.
3. The **crypto layer** (`comms/crypto.c`) encrypts each event using AES-256-GCM. Session keys are derived from a master key via HKDF-SHA256, with support for key rotation.
4. Encrypted frames are queued in the **character device** (`/dev/photon_ring`) ring buffer for userspace consumption.
5. The **userspace agent** (`photon_agent`) connects to a remote server over TLS 1.3 with mutual authentication (mTLS), performs a key exchange (the server generates a 32-byte master key and the agent injects it into the kernel via ioctl), then continuously reads encrypted frames from `/dev/photon_ring` and relays them to the server without decrypting.
6. The **remote server** (`python_tools/server.py`) replicates the kernel's HKDF key derivation, decrypts each frame, parses the `photon_event` struct, and bulk-indexes the event into Elasticsearch.

### Fallback Path — dmesg Polling

1. Detectors also log to the kernel ring buffer via `printk`, tagged with `[PHOTON RING]`.
2. The **Python daemon** (`python_tools/main.py`) polls dmesg, regex-parses the messages into structured events with per-event severity levels (`critical`, `high`, `medium`, `info`), and extracts fields (PID, process name, target symbols, paths, etc.).
3. Events are logged to daily JSONL files (`data/logs/`) and bulk-indexed into Elasticsearch.

### Visualization

**Kibana** provides a real-time web dashboard for searching, filtering, and visualizing detection events by severity, detector, and event type. Both data paths write to the same `lksm_events` index, so all detections appear in a single dashboard. See `es_payload_structure.md` for the full Elasticsearch document schema.

### Current Detectors

The module includes 20 detectors. 4 are active by default; the remaining 16 are fully implemented and can be enabled in `main.c`.

| Detector | Hooked Function(s) | What It Detects |
|----------|-------------------|-----------------|
| **kprobe_detector** | `register_kprobe` | Monitors kprobe registrations; flags suspicious probes (e.g. `kallsyms_lookup_name`) |
| **kretprobe_detector** | `register_kretprobe`, `register_kprobes` | Monitors return probe registrations; flags high maxactive values and batch registrations |
| **kallsyms_detector** | `kallsyms_lookup_name` (ftrace) | Monitors runtime symbol resolution; flags watchlisted symbol lookups (rootkit reconnaissance) |
| **ftrace_direct_detector** | `ftrace_set_filter`, `ftrace_set_notrace`, `modify_ftrace_direct` (kprobes) | Detects ftrace filter/notrace modifications and direct-call patching |
| **become_root_detector** | `commit_creds` | Detects privilege escalation — non-root processes gaining root credentials |
| **bpf_hook_detector** | `ftrace_set_filter_ip` (kprobe) | Detects ftrace hooks on 13 BPF-critical functions |
| **tcp_hiding_detector** | `ftrace_set_filter_ip` (kprobe) | Detects hooks on `tcp4/6_seq_show`, `udp4/6_seq_show`, `tpacket_rcv` |
| **icmp_hook_detector** | `ftrace_set_filter_ip` (kprobe) | Detects hooks on `icmp_rcv` (ICMP backdoor detection) |
| **reset_tainted_detector** | `kthread_create_on_node` + periodic polling | Detects suspicious kthreads, taint mask clearing, and hidden tasks |
| **clear_taint_dmesg_detector** | `do_syslog` (kprobe) | Detects kernel ring buffer clearing and suspicious reads |
| **trace_pid_detector** | `tracepoint_probe_register` | Detects PID-hiding tracepoint hooks on sched_process_fork/exec/exit |
| **hiding_stat_detector** | stat/lstat/fstatat/statx syscalls | Cross-verifies PID existence in tasklist vs. /proc VFS entries |
| **hiding_directory_detector** | `getdents`, `getdents64` | Audits directory enumeration for hidden entries |
| **hiding_chdir_detector** | `__x64_sys_chdir` / `__arm64_sys_chdir` | Flags chdir to sensitive paths (`/proc/`, `/.hidden/`, `/dev/shm/`) |
| **hiding_readlink_detector** | `vfs_readlink` | Flags readlink on module paths (`.ko`) and exe symlinks |
| **hooks_write_detector** | `vfs_write` (kprobe) | Detects writes to ftrace control files (e.g. `set_ftrace_filter`) |
| **hook_file_access_detector** | `do_filp_open` (kretprobe) | Tracks sensitive file access with full context (PID, UID, flags) |
| **lkrg_bypass_detector** | `vprintk_emit`, `call_usermodehelper_exec` | Detects LKRG message filtering and usermode helper execution |
| **taskstats_hook_detector** | `genl_register_family`, `cn_add_callback`, `taskstats_exit` | Monitors taskstats, generic netlink, and process connector hooks |
| **hooking_audit_detector** | `netlink_unicast`, `audit_log_start`, `audit_log_end`, `__audit_syscall_entry` | Monitors audit subsystem hooks and evasion attempts |

### Architecture Portability

The module supports both **x86_64** and **ARM64** via `photon_ring_arch.h`, which provides portable macros for extracting function arguments from ftrace and kprobe register snapshots. On x86_64 it maps to RDI/RSI/RDX/RCX/R8/R9; on ARM64 it maps to X0-X7. Modern kernels (6.x+) use `ftrace_regs_get_argument()` with a fallback to direct `pt_regs` access on older kernels.

## Team

- Team Number: Group 32
- Team Members: Jamie King, Brett Balquist, Kaden Huber, Hart Nurnberg, Max Biundo, & Dustin Le

### Link to project board: https://github.com/users/brett-b112/projects/1

## License

MIT
