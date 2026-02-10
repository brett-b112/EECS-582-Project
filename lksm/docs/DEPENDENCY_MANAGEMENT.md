# Dependency Management

## Environment Setup

Run the setup script to install all dependencies and create a Python virtual environment:

```bash
bash setup.sh
```

This installs system packages (gcc, kernel headers, kmod), creates a Python
venv, and installs Python dependencies from `requirements.txt`.

## Python Dependencies

Always use the virtual environment:

```bash
source venv/bin/activate
```

### Installing dependencies

After cloning or pulling, install/update all Python packages:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

This includes Flask (for the web dashboard), PyYAML, pytest, and other
project dependencies.

### Adding a new package

```bash
source venv/bin/activate
pip install new-package
pip show new-package   # note the version

# Pin it in requirements.txt
echo "new-package==X.Y.Z" >> requirements.txt

# Commit and tell your team to run: pip install -r requirements.txt
```

Always pin exact versions (`==`) in `requirements.txt`.

### Syncing after a pull

```bash
git pull
source venv/bin/activate
pip install -r requirements.txt
```

## Using sudo with the Virtual Environment

Some LKSM tools (e.g. the dashboard) need root access to read the kernel ring
buffer via `dmesg`. When running with `sudo`, the shell does **not** see your
activated venv, so `sudo python` will fail with "command not found".

Always use the full path to the venv Python binary:

```bash
sudo venv/bin/python -m python_tools.main --mode dashboard
```

Alternatively, relax the `dmesg` restriction so root is not required:

```bash
sudo sysctl kernel.dmesg_restrict=0
python -m python_tools.main --mode dashboard
```

## Kernel Module

The kernel module is built against the headers for the currently running kernel.
After a kernel update, reinstall headers and rebuild:

```bash
sudo apt install linux-headers-$(uname -r)
cd kernel_module
make clean && make
```

## Verifying Your Environment

```bash
python check_versions.py     # Check Python, GCC, kernel
make test-env                # Check venv, tools, headers
make verify-kernel           # Check kernel config options
```

## Fresh Start

```bash
make clean-venv   # Remove venv
bash setup.sh     # Rebuild everything
```
