# PHOTON RING
<img width="500" height="500" alt="photon_ring_logo" src="https://github.com/user-attachments/assets/4c139850-ec36-4381-98c4-fa9b5222bb18" />

A kernel module that detects rootkit-style activity (kprobe hooking, audit evasion, taskstats manipulation, privilege escalation) and streams detections to Elasticsearch for real-time visualization in Kibana.

## Project Structure

```
lksm/
├── docker-compose.yml         # Elasticsearch + Kibana stack
├── kernel_module/             # The kernel module (C)
│   ├── Makefile
│   ├── main.c                 # Entry point, loads all detectors
│   ├── include/               # Header files
│   └── modules/               # Detector implementations
│       ├── kprobe_detector.c
│       ├── hooking_audit_detector.c
│       ├── taskstats_hook_detector.c
│       └── become_root_detector.c
├── python_tools/              # Event reader and ES indexer (Python)
│   ├── main.py                # CLI entry point
│   ├── core/                  # Event parsing from dmesg
│   └── output/                # Elasticsearch writer + JSON logger
├── scripts/
│   └── setup_kibana.py        # One-time Kibana data view setup
├── config/                    # Default configuration files
├── data/logs/                 # Event logs (created at runtime)
└── requirements.txt           # Python dependencies
```

## Prerequisites 
## MUST BE INSTALLED ON YOUR MACHINE

- Ubuntu/Debian Linux
- Python 3.8+
- Docker and Docker Compose

Install the required system packages:

```bash
sudo apt install build-essential linux-headers-$(uname -r) python3-venv docker docker-compose
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

| Command          | What it does                          |
|------------------|---------------------------------------|
| `make`           | Build the module                      |
| `make clean`     | Remove build artifacts                |
| `make install`   | Build and load the module             |
| `make uninstall` | Unload the module                     |
| `make reload`    | Unload, clean, rebuild, and reload    |
| `make logs`      | Show recent kernel logs               |
| `make status`    | Check if the module is loaded         |

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

1. The **kernel module** hooks into kernel functions using ftrace and logs suspicious activity via `printk` to the kernel ring buffer (dmesg), tagged with `[PHOTON RING]`.
2. The **Python daemon** polls `dmesg` for these messages, parses them into structured events, logs them to JSONL files, and bulk-indexes them into Elasticsearch.
3. **Kibana** provides a real-time web dashboard for searching, filtering, and visualizing detection events.

### Current Detectors

| Detector | Hooked Function(s) | What It Detects |
|----------|-------------------|-----------------|
| **kprobe_detector** | `register_kprobe` | Monitors kprobe registrations; flags suspicious probes (e.g. `kallsyms_lookup_name`) |
| **taskstats_hook_detector** | `genl_register_family`, `cn_add_callback`, `taskstats_exit` | Monitors taskstats, generic netlink, and process connector hooks |
| **hooking_audit_detector** | `netlink_unicast`, `audit_log_start`, `audit_log_end`, `__audit_syscall_entry` | Monitors audit subsystem hooks and evasion attempts |
| **become_root_detector** | `commit_creds` | Detects privilege escalation — non-root processes gaining root credentials |

## Team

- Team Number: Group 32
- Team Members: Jamie King, Brett Balquist, Kaden Huber, Hart Nurnberg, Max Biundo, & Dustin Le

## License

MIT
