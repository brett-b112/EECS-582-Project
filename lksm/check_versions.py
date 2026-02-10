#!/usr/bin/env python3
"""
LKSM Dependency Version Checker
Verifies that all team members have compatible dependency versions
"""

import sys
import subprocess
import platform
from pathlib import Path

# Expected versions (update these as needed)
EXPECTED_VERSIONS = {
    'python_min': (3, 8),
    'python_max': (3, 13),
    'gcc_min': 9,
    'kernel_min': (5, 10),
}

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print("=" * len(text))

def print_success(text):
    print(f"{Colors.GREEN}✓{Colors.RESET} {text}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {text}")

def print_error(text):
    print(f"{Colors.RED}✗{Colors.RESET} {text}")

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    current = (version.major, version.minor)
    
    print_header("Python Version")
    print(f"Current: {version.major}.{version.minor}.{version.micro}")
    
    min_ver = EXPECTED_VERSIONS['python_min']
    max_ver = EXPECTED_VERSIONS['python_max']
    
    if current < min_ver:
        print_error(f"Python {min_ver[0]}.{min_ver[1]}+ required")
        return False
    elif current > max_ver:
        print_warning(f"Python {current[0]}.{current[1]} is newer than tested version {max_ver[0]}.{max_ver[1]}")
        return True
    else:
        print_success(f"Compatible version (>={min_ver[0]}.{min_ver[1]}, <={max_ver[0]}.{max_ver[1]})")
        return True

def check_virtual_env():
    """Check if running in virtual environment"""
    print_header("Virtual Environment")
    
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    
    if in_venv:
        print_success("Running in virtual environment")
        return True
    else:
        print_warning("NOT in virtual environment (run 'source venv/bin/activate')")
        return False

def check_gcc():
    """Check GCC version"""
    print_header("GCC Compiler")
    
    try:
        result = subprocess.run(['gcc', '--version'], 
                              capture_output=True, text=True, check=True)
        version_line = result.stdout.split('\n')[0]
        print(f"Installed: {version_line}")
        
        # Extract version number (rough parsing)
        import re
        match = re.search(r'(\d+)\.\d+\.\d+', version_line)
        if match:
            major = int(match.group(1))
            min_gcc = EXPECTED_VERSIONS['gcc_min']
            if major >= min_gcc:
                print_success(f"GCC {major} (>={min_gcc} required)")
                return True
            else:
                print_error(f"GCC {min_gcc}+ required")
                return False
        else:
            print_warning("Could not parse GCC version")
            return True
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error("GCC not found")
        return False

def check_kernel_version():
    """Check kernel version"""
    print_header("Linux Kernel")
    
    kernel = platform.release()
    print(f"Current: {kernel}")
    
    # Parse version (e.g., "5.15.0-91-generic" -> (5, 15))
    try:
        parts = kernel.split('.')
        major = int(parts[0])
        minor = int(parts[1])
        current = (major, minor)
        
        min_kernel = EXPECTED_VERSIONS['kernel_min']
        if current >= min_kernel:
            print_success(f"Kernel {major}.{minor} (>={min_kernel[0]}.{min_kernel[1]} required)")
            return True
        else:
            print_error(f"Kernel {min_kernel[0]}.{min_kernel[1]}+ required")
            return False
    except:
        print_warning("Could not parse kernel version")
        return True

def check_kernel_headers():
    """Check if kernel headers are installed"""
    print_header("Kernel Headers")
    
    kernel = platform.release()
    headers_path = Path(f"/lib/modules/{kernel}/build")
    
    if headers_path.exists():
        print_success(f"Headers found for kernel {kernel}")
        return True
    else:
        print_error(f"Headers not found for kernel {kernel}")
        print(f"  Install with: sudo apt install linux-headers-{kernel}")
        return False

def check_python_packages():
    """Check Python package versions"""
    print_header("Python Packages")
    
    requirements_file = Path('requirements.txt')
    if not requirements_file.exists():
        print_warning("requirements.txt not found")
        return True
    
    try:
        import pkg_resources
        
        with open(requirements_file) as f:
            requirements = [line.strip() for line in f 
                          if line.strip() and not line.startswith('#')]
        
        issues = []
        for req in requirements[:10]:  # Check first 10
            try:
                pkg_resources.require(req)
            except Exception as e:
                issues.append(f"  {req}: {str(e)[:50]}")
        
        if issues:
            print_error(f"Package version mismatches:")
            for issue in issues:
                print(issue)
            print(f"\n  Run: pip install -r requirements.txt")
            return False
        else:
            print_success("All package versions match requirements.txt")
            return True
            
    except ImportError:
        print_warning("Cannot verify package versions (setuptools not installed)")
        return True

def main():
    """Run all checks"""
    print(f"{Colors.BOLD}LKSM Dependency Version Checker{Colors.RESET}")
    print("=" * 50)
    
    checks = [
        ("Python Version", check_python_version),
        ("Virtual Environment", check_virtual_env),
        ("GCC Compiler", check_gcc),
        ("Kernel Version", check_kernel_version),
        ("Kernel Headers", check_kernel_headers),
        ("Python Packages", check_python_packages),
    ]
    
    results = {}
    for name, check_func in checks:
        try:
            results[name] = check_func()
        except Exception as e:
            print_error(f"Error checking {name}: {e}")
            results[name] = False
    
    # Summary
    print_header("Summary")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print_success("\nAll checks passed! Environment is ready.")
        return 0
    else:
        print_warning(f"\n{total - passed} check(s) failed. See above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
