# LKSM Dependency Management - Quick Reference

## 📦 Files Included

1. **requirements.txt** - Pinned Python dependencies
2. **KERNEL_DEPENDENCIES.md** - System package requirements
3. **setup.sh** - Automated environment setup script
4. **Makefile** - Commands for managing the environment
5. **DEPENDENCY_MANAGEMENT.md** - Comprehensive guide
6. **.gitignore** - Git ignore rules for the project
7. **check_versions.py** - Verify environment compatibility

## 🚀 Quick Start for New Team Members

```bash
# 1. Clone the repository
git clone <your-repo>
cd lksm

# 2. Run automated setup
bash setup.sh

# 3. Activate Python environment
source venv/bin/activate

# 4. Verify everything is working
python check_versions.py
make test-env
```

## 🔑 Key Commands

### Environment Setup
```bash
make setup          # Run full setup
make test-env       # Verify environment
make verify-kernel  # Check kernel configuration
```

### Daily Workflow
```bash
source venv/bin/activate    # Always run this first!
python check_versions.py    # Verify versions
```

### Adding Dependencies
```bash
# 1. Add to requirements.txt with exact version
echo "new-package==1.2.3" >> requirements.txt

# 2. Install it
pip install -r requirements.txt

# 3. Commit and notify team
git add requirements.txt
git commit -m "Add new-package dependency"
git push
```

## 📋 Ensuring Same Versions Across Team

### Python Dependencies
- ✅ **Always pin exact versions** in requirements.txt
- ✅ Use virtual environments (`venv/`)
- ✅ Never use version ranges like `>=1.0`

Example:
```
PyYAML==6.0.1        # Good - exact version
PyYAML>=6.0          # Bad - could be 6.0, 6.1, 7.0...
```

### System Dependencies
- ✅ Use the **same OS/version** across team (e.g., Ubuntu 22.04)
- ✅ Document kernel version: `uname -r`
- ✅ Run `setup.sh` to install system packages

### Verification
Run these to ensure consistency:
```bash
python check_versions.py    # Check Python, GCC, kernel
make test-env               # Full environment check
pip list                    # Show installed packages
```

## 🎯 Best Practices

### DO:
✅ Always activate venv before working
✅ Pin exact versions in requirements.txt
✅ Commit requirements.txt to git
✅ Run check_versions.py regularly
✅ Test before committing dependency changes

### DON'T:
❌ Use `sudo pip install` (system-wide install)
❌ Commit `venv/` directory to git
❌ Use version ranges in requirements.txt
❌ Install packages without updating requirements.txt

## 🔧 Common Issues & Solutions

### "Command not found" errors
```bash
# Make sure you activated the virtual environment
source venv/bin/activate
```

### "Permission denied" when installing
```bash
# Don't use sudo! Use virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

### "Kernel headers not found"
```bash
# Install headers for your current kernel
sudo apt install linux-headers-$(uname -r)
```

### Dependencies out of sync
```bash
# Pull latest code
git pull

# Reinstall dependencies
source venv/bin/activate
pip install -r requirements.txt
```

### Fresh start needed
```bash
# Remove virtual environment
make clean-venv

# Run setup again
make setup
```

## 📚 Documentation Structure

- **DEPENDENCY_MANAGEMENT.md** - Full guide with scenarios and troubleshooting
- **KERNEL_DEPENDENCIES.md** - System package details
- **This file** - Quick reference for common tasks

## 🎓 For School Projects Without CI/CD

Since you won't be using containers or CI/CD, **consistency depends on:**

1. **Communication** - Notify team when dependencies change
2. **Virtual environments** - Isolate project dependencies
3. **Version pinning** - Lock exact versions
4. **Regular checks** - Run `check_versions.py` frequently
5. **Same OS** - Ideally use same Linux distro/version

## 📝 Team Coordination

When someone adds a dependency:
1. Update `requirements.txt` with exact version
2. Commit and push
3. Notify team via Slack/Discord/Email: "New dependency added, run `pip install -r requirements.txt`"

## 🆘 Getting Help

1. Read DEPENDENCY_MANAGEMENT.md
2. Run `make test-env` and `python check_versions.py`
3. Check error messages carefully
4. Ask team members
5. Update documentation when you find solutions!

---

**Remember:** The goal is reproducibility. Every team member should be able to run the same code with the same results!
