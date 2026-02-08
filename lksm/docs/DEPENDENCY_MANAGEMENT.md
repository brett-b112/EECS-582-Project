# LKSM Dependency Management Guide

This guide explains how to ensure all team members have the same development environment for the LKSM project.

## Quick Start

For new team members joining the project:

```bash
# Clone the repository
git clone <your-repo-url>
cd lksm

# Run the setup script
bash setup.sh

# Verify your environment
make test-env
```

That's it! The setup script will handle everything.

## Files Overview

### `requirements.txt`
Contains **pinned Python dependencies** with exact version numbers. This ensures everyone uses the same library versions.

**Important:** Never run `pip install <package>` directly. Always add to `requirements.txt` first!

### `KERNEL_DEPENDENCIES.md`
Documents the system packages needed for kernel module development (gcc, kernel headers, etc.).

### `setup.sh`
Automated setup script that:
1. Installs system dependencies (kernel headers, build tools)
2. Creates a Python virtual environment
3. Installs Python dependencies from `requirements.txt`
4. Verifies kernel configuration

### `Makefile`
Provides convenient commands for managing the development environment.

## Ensuring Consistent Dependencies

### For Python Dependencies

#### Adding a New Dependency

1. **Add to requirements.txt with a pinned version:**
   ```
   new-package==1.2.3
   ```

2. **Install in your virtual environment:**
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Commit the updated requirements.txt:**
   ```bash
   git add requirements.txt
   git commit -m "Add new-package dependency"
   git push
   ```

4. **Notify team members** to run:
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

#### Why Pin Versions?

Without pinning:
```
PyYAML>=6.0  # Bad: Could install 6.0, 6.1, 7.0...
```

With pinning:
```
PyYAML==6.0.1  # Good: Everyone gets exactly 6.0.1
```

This prevents "works on my machine" issues!

### For System Dependencies

System packages (gcc, kernel headers) are harder to pin because they depend on the OS. The `setup.sh` script installs what's available in your OS repositories.

**Best practices:**
- Document your development OS in the team wiki
- Use the same Linux distribution version across the team (e.g., Ubuntu 22.04 LTS)
- If using VMs, share a base VM image

## Virtual Environments

### Why Use a Virtual Environment?

A Python virtual environment isolates your project dependencies from system Python. This prevents:
- Version conflicts with other projects
- Accidentally breaking system tools
- Permission issues when installing packages

### Using the Virtual Environment

**Activate it:**
```bash
source venv/bin/activate
```

Your prompt will change to show `(venv)`.

**Deactivate it:**
```bash
deactivate
```

**Always activate before working on the project!**

## Common Scenarios

### Scenario 1: New Team Member Setup

```bash
# Clone the repo
git clone <repo-url>
cd lksm

# Run setup
bash setup.sh

# Activate virtual environment
source venv/bin/activate

# Verify everything works
make test-env
```

### Scenario 2: Someone Added a New Python Package

```bash
# Pull the latest code
git pull

# Activate virtual environment
source venv/bin/activate

# Install new dependencies
pip install -r requirements.txt
```

### Scenario 3: You Need to Add a Package

```bash
# Activate virtual environment
source venv/bin/activate

# Install the package temporarily to test
pip install new-package

# If it works, find the exact version
pip show new-package  # Look for "Version: X.Y.Z"

# Add to requirements.txt with exact version
echo "new-package==X.Y.Z" >> requirements.txt

# Commit and push
git add requirements.txt
git commit -m "Add new-package dependency"
git push

# Notify team on Slack/Discord/Email
```

### Scenario 4: Dependency Conflict

If you get an error like:
```
ERROR: package-a requires package-b>=2.0, but you have package-b==1.5
```

**Solution:**
1. Check if both packages are truly needed
2. Try updating the conflicting package:
   ```bash
   pip install package-b==2.0.1
   ```
3. Test that everything still works
4. Update requirements.txt with the new version
5. Commit and notify team

### Scenario 5: Fresh Start

If your environment gets messed up:

```bash
# Remove the virtual environment
make clean-venv

# Or manually:
rm -rf venv

# Run setup again
bash setup.sh
```

## Verifying Your Environment

Run these commands to verify your setup:

```bash
# Check all environment variables
make test-env

# Check kernel configuration
make verify-kernel

# List installed Python packages
source venv/bin/activate
pip list
```

## Kernel Module Dependencies

Kernel modules are compiled against specific kernel headers. **Critical rules:**

1. **Everyone should use the same kernel version if possible**
   - Check with: `uname -r`
   - Example: `5.15.0-91-generic`

2. **Install kernel headers for your running kernel:**
   ```bash
   sudo apt install linux-headers-$(uname -r)
   ```

3. **If you update your kernel, reinstall headers:**
   ```bash
   sudo apt install linux-headers-$(uname -r)
   ```

## Best Practices

### DO:
✅ Always work in the virtual environment (`source venv/bin/activate`)
✅ Pin exact versions in requirements.txt
✅ Test changes before committing requirements.txt
✅ Document why you added each dependency
✅ Communicate dependency changes to the team

### DON'T:
❌ Install Python packages globally (`sudo pip install`)
❌ Use version ranges (`package>=1.0`)
❌ Commit the `venv/` directory to git
❌ Mix Python 2 and Python 3
❌ Forget to activate the virtual environment

## Troubleshooting

### "pip: command not found"

Make sure you activated the virtual environment:
```bash
source venv/bin/activate
```

### "Permission denied" when installing packages

Don't use `sudo pip`! Make sure you're in the virtual environment.

### "kernel headers not found"

Install headers for your current kernel:
```bash
sudo apt install linux-headers-$(uname -r)
```

### "module won't load"

Check that your kernel was compiled with the required options:
```bash
make verify-kernel
```

## Git Workflow

**Files to commit:**
- ✅ `requirements.txt`
- ✅ `KERNEL_DEPENDENCIES.md`
- ✅ `setup.sh`
- ✅ `Makefile`
- ✅ This README

**Files to ignore (add to .gitignore):**
- ❌ `venv/`
- ❌ `__pycache__/`
- ❌ `*.pyc`
- ❌ `.pytest_cache/`
- ❌ `requirements-frozen.txt` (optional, only for debugging)

## Getting Help

If you run into issues:

1. Check this README
2. Run `make test-env` to diagnose
3. Ask on the team Slack/Discord
4. Check the error message carefully

## Updating This Guide

As you discover issues or solutions, **update this README**! Future team members will thank you.
