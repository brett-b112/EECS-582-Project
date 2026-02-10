#!/usr/bin/env python3
"""
LKSM - Linux Kernel Security Monitor
Main entry point for Python analysis tools
"""

import argparse
import sys
import threading
import time
from pathlib import Path

import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from python_tools.core.module_base import ModuleRegistry
from python_tools.output.json_logger import EventLogger
from python_tools.output.dashboard import create_app, push_events


def load_config(path: str) -> dict:
    """Load YAML configuration file."""
    cfg_path = Path(path)
    if not cfg_path.exists():
        print(f"Warning: config {path} not found, using defaults")
        return {}
    with open(cfg_path) as f:
        return yaml.safe_load(f) or {}


def run_daemon(config: dict, stop_event: threading.Event | None = None) -> None:
    """Poll modules in a loop, log events, and push to dashboard."""
    registry = ModuleRegistry()
    registry.discover("python_tools.core.modules")
    registry.start_all(config)

    logger = EventLogger(config)
    interval = config.get("communication", {}).get("poll_interval", 1.0)

    print(f"Daemon running — modules: {registry.module_names}")
    try:
        while not (stop_event and stop_event.is_set()):
            events = registry.poll_all()
            if events:
                logger.log_events(events)
                push_events(events)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        registry.stop_all()
        print("Daemon stopped.")


def run_dashboard(config: dict) -> None:
    """Start daemon in a background thread, then run Flask in the foreground."""
    stop = threading.Event()
    daemon_thread = threading.Thread(target=run_daemon, args=(config, stop), daemon=True)
    daemon_thread.start()

    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "127.0.0.1")
    port = dash_cfg.get("port", 5000)

    app = create_app()
    print(f"Dashboard at http://{host}:{port}")
    try:
        app.run(host=host, port=port)
    finally:
        stop.set()


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
    config = load_config(args.config)

    if args.mode == 'dashboard':
        run_dashboard(config)
    elif args.mode == 'daemon':
        run_daemon(config)
    elif args.mode == 'analyze':
        if not args.file:
            print("Error: --file required for analyze mode")
            return 1
        print(f"Analyzing {args.file}...")

    return 0

if __name__ == '__main__':
    sys.exit(main())
