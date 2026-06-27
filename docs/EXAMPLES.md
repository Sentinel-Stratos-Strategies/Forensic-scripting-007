# Usage Examples

This document provides practical examples of using the forensic detection suite.

## Example 1: Basic System Scan

Scan your system for LLM/AI processes:

```bash
cd Forensic-scripting-007
./scripts/master_detector.sh
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════╗
║     LLM/AI FORENSIC DETECTION SUITE                          ║
║     Creative Forensics & Detection Framework                  ║
╚═══════════════════════════════════════════════════════════════╝

[*] Output directory: ./forensic_reports_20251205_120000
```

Results saved to timestamped directory.

## Example 2: Investigating Specific Process

If you found a suspicious PID (e.g., 1234):

```bash
# Check process details
ps aux | grep 1234

# Check memory maps
cat /proc/1234/maps

# Check environment variables
cat /proc/1234/environ | tr '\0' '\n'

# Check open files
lsof -p 1234

# Monitor syscalls (requires root)
sudo strace -p 1234 -c
```

## Example 3: Continuous Monitoring

Monitor system every 5 minutes:

```bash
#!/bin/bash
while true; do
    echo "[$(date)] Running scan..."
    python3 scripts/anomaly_detector.py > /tmp/scan_$(date +%s).txt
    
    # Alert if findings detected
    if grep -q "\[!\]" /tmp/scan_*.txt; then
        echo "Alert: Suspicious activity detected!"
    fi
    
    sleep 300
done
```

## Example 4: Targeted Scan

Scan only specific directories for model files:

```bash
# Search for PyTorch models
find ~/.cache -name "*.pt" -o -name "*.pth" 2>/dev/null

# Search for TensorFlow models
find ~/.cache -name "*.pb" -o -name "*.h5" 2>/dev/null

# Search for ONNX models
find ~/.cache -name "*.onnx" 2>/dev/null

# Check sizes
du -sh ~/.cache/huggingface 2>/dev/null
du -sh ~/.cache/torch 2>/dev/null
```

## Example 5: Network Traffic Analysis

Monitor network connections:

```bash
# List all ESTABLISHED connections
netstat -tn | grep ESTABLISHED

# Monitor specific port (e.g., 8000)
sudo tcpdump -i any port 8000 -nn

# Save capture for analysis
sudo tcpdump -i any port 8000 -w capture.pcap

# Analyze with tshark
tshark -r capture.pcap
```

## Example 6: Using htop with Findings

After running anomaly detector:

```bash
# Get suspicious PIDs
python3 scripts/anomaly_detector.py | grep "PID" | awk '{print $2}' | tr -d ':'

# Monitor them in htop
htop -p 1234,5678,9012
```

## Example 7: Automated Alerting

Create a cron job for regular scans:

```bash
# Edit crontab
crontab -e

# Add line (run every hour):
0 * * * * cd /path/to/Forensic-scripting-007 && python3 scripts/anomaly_detector.py > /var/log/forensic_scan.log 2>&1
```

## Example 8: JSON Report Analysis

Parse JSON reports programmatically:

```python
import json

# Load report
with open('anomaly_report.json', 'r') as f:
    report = json.load(f)

# Count findings by type
for category, findings in report['anomalies'].items():
    print(f"{category}: {len(findings)} findings")

# Extract PIDs of high-memory processes
high_mem_pids = [
    item['pid'] 
    for item in report['anomalies'].get('high_memory', [])
]
print(f"High memory PIDs: {high_mem_pids}")
```

## Example 9: Investigating GPU Usage

Check for GPU-accelerated AI processes:

```bash
# Check NVIDIA GPUs (if available)
nvidia-smi

# Check processes using GPU
nvidia-smi pmon

# Check CUDA processes
lsof /dev/nvidia*

# Check AMD GPUs (if available)
radeontop
```

## Example 10: Log Analysis Deep Dive

Detailed log investigation:

```bash
# Run log analyzer
sudo python3 scripts/log_analyzer.py

# Manual syslog check
sudo grep -i "gpu\|cuda\|model\|inference" /var/log/syslog

# Check auth log for suspicious logins
sudo grep -i "session opened\|session closed" /var/log/auth.log

# Check journalctl
sudo journalctl -u '*' --since "1 hour ago" | grep -i "model\|inference"
```

## Example 11: Memory Forensics

Analyze process memory:

```bash
# Check memory usage by process
ps aux --sort=-%mem | head -20

# Detailed memory info for a process
cat /proc/1234/status | grep -E "VmSize|VmRSS|VmData"

# Check memory maps
cat /proc/1234/maps | grep -i anon

# Check for large allocations
cat /proc/1234/smaps | grep -E "Size|Rss"
```

## Example 12: Behavioral Monitoring

Deep behavioral analysis:

```bash
# Monitor file operations (requires root)
sudo strace -e trace=file -p 1234 2>&1 | tee file_ops.log

# Monitor network operations
sudo strace -e trace=network -p 1234 2>&1 | tee network_ops.log

# Monitor memory operations
sudo strace -e trace=memory -p 1234 2>&1 | tee memory_ops.log

# Full syscall trace
sudo strace -p 1234 -c
```

## Example 13: Port Scanning

Check for API servers:

```bash
# Check common AI API ports
for port in 8000 8080 5000 7860 11434; do
    netstat -tln | grep ":$port " && echo "Port $port is listening"
done

# Identify process on specific port
lsof -i :8000

# Check all listening ports
netstat -tlnp | grep LISTEN
```

## Example 14: Environment Analysis

Check environment variables system-wide:

```bash
# Check for AI-related env vars in all processes
for pid in $(pgrep .); do
    env_file="/proc/$pid/environ"
    if [ -f "$env_file" ]; then
        if grep -q "CUDA\|HF_\|TORCH\|OPENAI\|ANTHROPIC" "$env_file" 2>/dev/null; then
            echo "PID $pid has AI-related environment variables"
            cat "$env_file" | tr '\0' '\n' | grep "CUDA\|HF_\|TORCH\|OPENAI\|ANTHROPIC"
        fi
    fi
done
```

## Example 15: Report Comparison

Compare scans over time:

```bash
# Run scan 1
python3 scripts/anomaly_detector.py
mv anomaly_report.json anomaly_report_1.json

# Wait or make changes...
sleep 3600

# Run scan 2
python3 scripts/anomaly_detector.py
mv anomaly_report.json anomaly_report_2.json

# Compare
diff <(jq -S . anomaly_report_1.json) <(jq -S . anomaly_report_2.json)
```

## Example 16: Whitelisting Known Processes

Filter out legitimate processes:

```python
import json

# Known legitimate PIDs or process names
WHITELIST = ['python3', 'vscode', 'pycharm']

# Load report
with open('anomaly_report.json', 'r') as f:
    report = json.load(f)

# Filter findings
filtered = {}
for category, findings in report['anomalies'].items():
    filtered[category] = [
        f for f in findings 
        if f.get('name', '') not in WHITELIST
    ]

# Show filtered results
for category, findings in filtered.items():
    if findings:
        print(f"\n{category}: {len(findings)} findings")
        for finding in findings:
            print(f"  - {finding}")
```

## Example 17: Integration with Security Tools

### With Splunk

```bash
# Send reports to Splunk
python3 scripts/anomaly_detector.py
curl -k https://splunk-server:8088/services/collector \
    -H "Authorization: Splunk YOUR-TOKEN" \
    -d @anomaly_report.json
```

### With ELK Stack

```bash
# Send to Elasticsearch
curl -X POST "localhost:9200/forensic-scans/_doc" \
    -H 'Content-Type: application/json' \
    -d @anomaly_report.json
```

### With Syslog

```bash
# Send findings to syslog
python3 scripts/anomaly_detector.py | logger -t forensic-scan
```

## Example 18: Incident Response Workflow

Complete incident response:

```bash
#!/bin/bash
# incident_response.sh

echo "[1] Running full forensic scan..."
sudo ./scripts/master_detector.sh

echo "[2] Identifying suspicious processes..."
SUSPICIOUS_PIDS=$(python3 scripts/anomaly_detector.py | grep "PID" | awk '{print $2}' | tr -d ':')

echo "[3] Gathering process information..."
for pid in $SUSPICIOUS_PIDS; do
    echo "=== PID $pid ==="
    ps -p $pid -o pid,ppid,cmd,user,%mem,%cpu
    lsof -p $pid | head -20
    cat /proc/$pid/environ | tr '\0' '\n' | head -10
done > incident_details.txt

echo "[4] Capturing network connections..."
netstat -tnp > network_snapshot.txt

echo "[5] Creating memory dump (if needed)..."
# gcore $SUSPICIOUS_PID  # Uncomment if needed

echo "[6] Generating report..."
echo "Incident Response Report - $(date)" > incident_report.txt
cat incident_details.txt >> incident_report.txt
cat network_snapshot.txt >> incident_report.txt

echo "Investigation complete. See incident_report.txt"
```

## Example 19: Testing Detection Capabilities

Create test case (for educational purposes):

```python
#!/usr/bin/env python3
# test_detection.py - Simulate LLM indicators for testing

import time
import os

# Set some environment variables that would trigger detection
os.environ['FAKE_TRANSFORMERS_CACHE'] = '/tmp/test'
os.environ['FAKE_CUDA_VISIBLE_DEVICES'] = '0'

# Allocate some memory
large_list = [0] * (100 * 1024 * 1024)  # ~800MB

# Keep process alive
print("Test process running. Run forensic scan in another terminal.")
print(f"PID: {os.getpid()}")
time.sleep(300)
```

Run this, then scan:
```bash
python3 test_detection.py &
TEST_PID=$!
python3 scripts/anomaly_detector.py
kill $TEST_PID
```

## Example 20: Persistence Sweep

Hunt for autorun hooks that could relaunch hidden AI workloads after reboot:

```bash
# Run the persistence detector
python3 scripts/persistence_detector.py

# Manually inspect suspicious entries
sudo grep -R "gpt\|llm\|model" /etc/systemd/system /etc/cron.* 2>/dev/null | head
sudo grep -R "OPENAI_API_KEY\|ANTHROPIC_API_KEY" ~/.bashrc ~/.profile /etc/profile 2>/dev/null | head
```

## Example 21: Comprehensive Security Audit

Full security audit script:

```bash
#!/bin/bash
# security_audit.sh

AUDIT_DIR="security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AUDIT_DIR"

echo "Starting comprehensive security audit..."

# 1. Forensic scan
echo "[1/6] Running forensic detection..."
./scripts/master_detector.sh
cp -r forensic_reports_*/* "$AUDIT_DIR/"

# 2. Process snapshot
echo "[2/6] Capturing process snapshot..."
ps auxf > "$AUDIT_DIR/process_tree.txt"

# 3. Network snapshot
echo "[3/6] Capturing network state..."
netstat -tulnp > "$AUDIT_DIR/network_state.txt" 2>&1
ss -tulnp > "$AUDIT_DIR/socket_state.txt" 2>&1

# 4. Installed packages
echo "[4/6] Listing installed packages..."
dpkg -l | grep -i "cuda\|nvidia\|tensor\|torch" > "$AUDIT_DIR/ai_packages.txt" 2>&1
pip list | grep -i "torch\|tensor\|transform" >> "$AUDIT_DIR/ai_packages.txt" 2>&1

# 5. System info
echo "[5/6] Gathering system info..."
uname -a > "$AUDIT_DIR/system_info.txt"
free -h >> "$AUDIT_DIR/system_info.txt"
df -h >> "$AUDIT_DIR/system_info.txt"

# 6. Create summary
echo "[6/6] Creating summary..."
cat > "$AUDIT_DIR/README.txt" << EOF
Security Audit Report
Date: $(date)
Host: $(hostname)

Files in this audit:
- Forensic scan results (multiple files)
- process_tree.txt: Process hierarchy
- network_state.txt: Network connections
- socket_state.txt: Socket information
- ai_packages.txt: AI/ML related packages
- system_info.txt: System information

Review all files for security concerns.
EOF

echo "Audit complete: $AUDIT_DIR"
tar -czf "$AUDIT_DIR.tar.gz" "$AUDIT_DIR"
echo "Archive created: $AUDIT_DIR.tar.gz"
```

## Tips and Best Practices

1. **Run with Root**: Many features require root access for full effectiveness
2. **Regular Scans**: Schedule scans to detect changes over time
3. **Baseline First**: Run initial scans on clean systems to establish baselines
4. **Investigate Patterns**: Look for multiple indicators, not just one
5. **Document Findings**: Keep detailed notes of investigations
6. **Update Signatures**: Periodically update detection patterns
7. **Test on Safe Systems**: Practice on authorized test systems first
8. **Secure Reports**: Store scan results securely (may contain sensitive data)
9. **Correlate Sources**: Use multiple detection methods together
10. **Manual Verification**: Always manually verify automated findings

## Getting Help

If you need assistance:
- Review the [Usage Guide](USAGE.md)
- Check the [Technical Details](TECHNICAL_DETAILS.md)
- Open an issue on GitHub
- Review script source code for inline documentation
