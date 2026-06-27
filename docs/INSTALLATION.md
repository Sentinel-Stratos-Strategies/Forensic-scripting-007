# Installation Guide

## System Requirements

### Supported Operating Systems

- Linux (Ubuntu, Debian, CentOS, RHEL, Fedora)
- macOS (limited support - some features Linux-specific)
- Windows WSL (Windows Subsystem for Linux)

### Required Software

- **Python 3.6 or higher**
- **pip** (Python package manager)
- **Bash** (for master script)

### Optional Tools (for Enhanced Detection)

- `strace` - System call tracer
- `lsof` - List open files
- `netstat` or `ss` - Network statistics
- `htop` - Interactive process viewer
- `wireshark` / `tcpdump` - Network traffic analysis

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007.git
cd Forensic-scripting-007
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or with Python 3 explicitly:

```bash
pip3 install -r requirements.txt
```

### 3. Make Scripts Executable

```bash
chmod +x scripts/*.sh scripts/*.py
```

### 4. (Optional) Install System Tools

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y lsof strace net-tools htop
```

#### CentOS/RHEL/Fedora

```bash
sudo yum install -y lsof strace net-tools htop
```

#### macOS

```bash
brew install lsof
# Note: strace not available on macOS, use dtruss instead
```

### 5. Verify Installation

Test that everything is installed correctly:

```bash
# Check Python version
python3 --version

# Check psutil installation
python3 -c "import psutil; print('psutil version:', psutil.__version__)"

# Check script permissions
ls -l scripts/

# Try running a simple scan (no root required)
python3 scripts/anomaly_detector.py
```

## Platform-Specific Notes

### Linux

Full functionality available. For complete system access:

```bash
# Run scripts with sudo for full capabilities
sudo python3 scripts/anomaly_detector.py
```

### macOS

- Some features may be limited due to OS differences
- `strace` is not available; use `dtruss` instead (requires root)
- `/proc` filesystem not available; some checks will be skipped

### Windows (WSL)

1. Install WSL2 with Ubuntu:
   ```powershell
   wsl --install -d Ubuntu
   ```

2. Open Ubuntu terminal and follow Linux installation steps

3. Note: Some system inspection features may be limited in WSL

## Permissions Setup

### Running as Non-Root User

Most detection features work without root, but with limitations:

```bash
python3 scripts/anomaly_detector.py
python3 scripts/signature_detector.py
python3 scripts/log_analyzer.py
```

### Running with Root Access

For full functionality (recommended for forensic analysis):

```bash
sudo python3 scripts/behavioral_analyzer.py
sudo python3 scripts/log_analyzer.py
sudo ./scripts/master_detector.sh
```

### Setting Up Sudo Access

If you need to run regularly with sudo, you can configure passwordless sudo for specific scripts:

```bash
# Edit sudoers file (use visudo for safety)
sudo visudo

# Add these lines (replace 'username' with your username):
username ALL=(ALL) NOPASSWD: /usr/bin/python3 /path/to/Forensic-scripting-007/scripts/anomaly_detector.py
username ALL=(ALL) NOPASSWD: /usr/bin/python3 /path/to/Forensic-scripting-007/scripts/behavioral_analyzer.py
username ALL=(ALL) NOPASSWD: /usr/bin/python3 /path/to/Forensic-scripting-007/scripts/log_analyzer.py
```

**Warning**: Only do this if you understand the security implications.

## Virtual Environment Setup (Recommended)

Using a virtual environment keeps dependencies isolated:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run scripts
python scripts/anomaly_detector.py

# Deactivate when done
deactivate
```

## Docker Installation (Alternative)

For containerized deployment:

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    lsof \
    strace \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ ./scripts/
COPY docs/ ./docs/

RUN chmod +x scripts/*.sh scripts/*.py

CMD ["/bin/bash"]
EOF

# Build image
docker build -t forensic-detector .

# Run container with host PID namespace for process inspection
docker run -it --pid=host --privileged forensic-detector

# Inside container, run scripts
python3 scripts/anomaly_detector.py
```

**Note**: Docker containers need `--pid=host` and `--privileged` to inspect host processes.

## Troubleshooting Installation

### "command not found: python3"

Install Python 3:

```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip

# macOS
brew install python3
```

### "ModuleNotFoundError: No module named 'psutil'"

Install psutil:

```bash
pip3 install psutil
# or
pip3 install -r requirements.txt
```

### Permission denied errors

Make scripts executable:

```bash
chmod +x scripts/*.sh scripts/*.py
```

### "strace: command not found"

Install strace:

```bash
# Ubuntu/Debian
sudo apt-get install strace

# CentOS/RHEL
sudo yum install strace
```

### Scripts run but show limited results

This is often due to lack of permissions. Try:

```bash
sudo python3 scripts/script_name.py
```

## Uninstallation

To remove the tools:

```bash
# Remove repository
cd ..
rm -rf Forensic-scripting-007

# Uninstall Python packages (if not using venv)
pip3 uninstall psutil

# If using virtual environment, just delete it
rm -rf venv
```

## Upgrading

To update to the latest version:

```bash
cd Forensic-scripting-007
git pull origin main
pip3 install -r requirements.txt --upgrade
```

## Getting Help

If you encounter issues:

1. Check this installation guide
2. Review the USAGE.md documentation
3. Check script output for error messages
4. Verify all dependencies are installed
5. Try running with sudo for full access
6. Open an issue on GitHub with details

## Next Steps

After installation:

1. Read the [Usage Guide](USAGE.md)
2. Run a test scan: `./scripts/master_detector.sh`
3. Review the generated reports
4. Explore individual detection scripts
5. Integrate with your security workflow

## Security Note

These forensic tools inspect system processes and files. Always:

- Review scripts before running with sudo
- Store reports securely (may contain sensitive info)
- Use in authorized environments only
- Follow your organization's security policies
- Keep tools updated for latest detection patterns
