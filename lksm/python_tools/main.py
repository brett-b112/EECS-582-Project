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
