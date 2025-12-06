# LLM/AI Forensic Detection Suite - Usage Guide

## Overview

This suite provides multiple detection methods for identifying hidden AI/LLM processes in a system. The tools use unconventional forensic techniques including:

- **Anomaly Detection**: Identifies processes with suspicious resource usage and behavior patterns
- **Signature-Based Detection**: Matches known LLM/AI framework signatures and patterns
- **Behavioral Analysis**: Monitors system calls and process behavior in real-time
- **Log Analysis**: Detects LLM activity and log tampering in system logs
- **Persistence Detection**: Finds autorun mechanisms that can quietly restart AI workloads

All detectors run locally and do not need internet access or API keys. If you want an offline LLM to help summarize results, see [LOCAL_LLM_OPTIONS](LOCAL_LLM_OPTIONS.md) for drop-in model suggestions.

## Quick Start

### Prerequisites

1. **Python 3.6+** is required
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional)** For full functionality, some tools require:
   - `strace` - for system call monitoring
   - `lsof` - for open file monitoring
   - `netstat` or `ss` - for network monitoring
   - Root/sudo access - for deep system inspection

### Installation

```bash
# Clone the repository
git clone https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007.git
cd Forensic-scripting-007

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh scripts/*.py
```

**Need a direct download instead of git?** Grab the ZIP from the main branch:

```bash
wget https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007/archive/refs/heads/main.zip -O forensic-suite.zip
unzip forensic-suite.zip
cd Forensic-scripting-007-main
```

Or pick a tagged archive from Releases for a versioned bundle:
https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007/releases

## Running the Tools

### Master Detection Script (Recommended)

Run all detection methods at once:

```bash
# Basic scan
./scripts/master_detector.sh

# Full scan with root privileges
sudo ./scripts/master_detector.sh
```

This will:
1. Run all detection scripts
2. Generate individual reports
3. Create a comprehensive summary
4. Save everything to a timestamped directory

### Individual Detection Scripts

#### 1. Anomaly Detector

Identifies processes with unusual resource usage and behavior:

```bash
python3 scripts/anomaly_detector.py
```

**What it detects:**
- Processes with LLM/AI-related names or command lines
- High memory usage (>1GB)
- High CPU usage (>50%)
- Suspicious network connections
- Unusual process parent-child relationships
- Processes with many child processes

**Output:**
- Console report with detailed findings
- `anomaly_report.json` - JSON formatted results

#### 2. Signature Detector

Uses pattern matching to find LLM frameworks and files:

```bash
python3 scripts/signature_detector.py
```

**What it detects:**
- Process command lines matching LLM patterns
- Environment variables indicating AI/LLM usage
- Open files with model signatures (.pt, .pb, .h5, .onnx)
- Processes listening on common API ports
- Model files in common cache directories

**Output:**
- Console report with categorized findings
- `signature_report.json` - JSON formatted results

#### 3. Behavioral Analyzer

Monitors process behavior and system calls:

```bash
# Basic analysis (10 seconds per process)
python3 scripts/behavioral_analyzer.py

# Extended analysis (30 seconds per process)
python3 scripts/behavioral_analyzer.py -d 30

# With root for full syscall monitoring
sudo python3 scripts/behavioral_analyzer.py -d 15
```

**What it detects:**
- Large anonymous memory regions (model loading)
- High thread counts (parallel inference)
- Suspicious system call patterns
- File access to model files

**Output:**
- Console report with behavioral patterns
- `behavioral_report.json` - JSON formatted results

**Note:** This script benefits most from root access for strace functionality.

#### 4. Log Analyzer

Analyzes system logs for LLM activity and tampering:

```bash
# Basic analysis
python3 scripts/log_analyzer.py

# With root for full log access
sudo python3 scripts/log_analyzer.py
```

**What it detects:**
- LLM/AI indicators in system logs
- Recently modified or empty log files
- Log tampering commands in bash history
- Suspicious log file permissions
- Evidence of log manipulation

**Output:**
- Console report with log findings
- `log_analysis_report.json` - JSON formatted results

#### 5. Persistence Detector

Finds startup hooks that could keep AI/LLM services running after reboot:

```bash
python3 scripts/persistence_detector.py
```

**What it detects:**
- Cron entries that launch model servers or reach out to AI APIs
- systemd unit files with AI/LLM indicators or embedded API keys
- Shell profile exports for AI credentials or tooling aliases
- Scheduled curl/wget calls to public AI endpoints

**Output:**
- Console report highlighting persistence mechanisms
- `persistence_report.json` - JSON formatted results

## Understanding the Reports

### Console Output

Each script provides a formatted console report with:
- Summary of findings by category
- Detailed information for each detection
- File paths, PIDs, and other identifying information

### JSON Reports

JSON reports are saved for programmatic analysis:

```json
{
  "timestamp": "2025-12-05T19:00:00",
  "anomalies": {
    "llm_indicators": [...],
    "high_memory": [...],
    "high_cpu": [...]
  }
}
```

## Detection Methods Explained

### 1. Process Name Analysis

Searches for keywords like:
- `transformer`, `pytorch`, `tensorflow`, `huggingface`
- `llama`, `gpt`, `bert`, `model`, `inference`
- `tokenizer`, `embedding`, `neural`, `cuda`, `gpu`

### 2. Resource Usage Analysis

Flags processes with:
- Memory usage > 1GB
- CPU usage > 50%
- Large anonymous memory regions (>100MB)

### 3. Network Connection Analysis

Monitors for connections to known LLM API services:
- OpenAI, Anthropic, Hugging Face
- Cohere, AI21, Replicate

### 4. File Signature Analysis

Looks for files with extensions:
- `.pt`, `.pth` (PyTorch)
- `.pb`, `.h5` (TensorFlow)
- `.onnx` (ONNX)
- `tokenizer.json`, `config.json`

### 5. System Call Analysis

Monitors suspicious syscalls:
- `mmap` (memory mapping for models)
- `mprotect` (memory protection)
- `futex` (thread synchronization)
- `openat` (file operations)

### 6. Log Integrity Analysis

Checks for:
- Empty or recently modified logs
- Suspicious permissions (777)
- Log deletion commands in history
- Timestamp gaps in logs

## Advanced Usage

### Continuous Monitoring

For continuous monitoring, run scripts in a loop:

```bash
while true; do
    python3 scripts/anomaly_detector.py
    sleep 300  # Check every 5 minutes
done
```

### Automated Alerting

Combine with system monitoring tools:

```bash
# Example: Alert if findings detected
python3 scripts/anomaly_detector.py > /tmp/scan.txt
if grep -q "\[!\]" /tmp/scan.txt; then
    echo "Alert: Suspicious activity detected!" | mail -s "Forensic Alert" admin@example.com
fi
```

### Integration with Other Tools

#### Using with htop

1. Run anomaly detector to get suspicious PIDs
2. Monitor them in htop: `htop -p PID1,PID2,PID3`

#### Using with Wireshark

1. Run signature detector to identify suspicious ports
2. Capture traffic: `sudo tcpdump -i any port 8000 -w capture.pcap`
3. Analyze in Wireshark

#### Using with strace

1. Identify target PID from reports
2. Trace syscalls: `sudo strace -p PID -c`

## Troubleshooting

### Permission Denied Errors

Many system inspection features require elevated privileges:

```bash
sudo python3 scripts/script_name.py
```

### Missing Dependencies

Install system tools:

```bash
# Ubuntu/Debian
sudo apt-get install lsof strace netstat-nat

# RHEL/CentOS
sudo yum install lsof strace net-tools
```

### No Findings Reported

This is good! It means:
- No obvious LLM processes detected
- System logs appear intact
- No suspicious resource usage patterns

However, sophisticated actors may evade detection. Consider:
- Running scans at different times
- Monitoring over longer periods
- Checking for processes masquerading as system daemons

## Best Practices

1. **Run with Root Privileges**: Many detection features require root access
2. **Regular Scanning**: Run scans periodically to establish baselines
3. **Review All Reports**: Check both console output and JSON files
4. **Correlate Findings**: Look for processes flagged by multiple detectors
5. **Manual Investigation**: Use findings as starting points for deeper analysis
6. **Document Results**: Keep scan reports for trend analysis

## Security Considerations

- Scripts read system information but don't modify anything
- JSON reports may contain sensitive paths and command lines
- Store reports securely if they contain sensitive information
- Root access is required for comprehensive analysis but increases risk
- Review scripts before running with elevated privileges

## Limitations

- **False Positives**: Legitimate AI/ML applications will be flagged
- **Evasion**: Sophisticated actors can rename processes and hide signatures
- **Performance**: Some scans can be resource-intensive
- **Compatibility**: Some features are Linux-specific
- **Permissions**: Many checks require root access

## Next Steps

After running scans:

1. **Review Findings**: Carefully examine all flagged processes
2. **Verify Legitimacy**: Check if flagged processes are authorized
3. **Deep Dive**: Use system tools for detailed investigation
4. **Correlate Data**: Look for patterns across multiple scans
5. **Take Action**: Terminate unauthorized processes, secure systems

## Support

For issues or questions:
- Check the documentation in `/docs`
- Review the script source code for detailed comments
- Open an issue on the GitHub repository

## Contributing

Contributions welcome! Areas for enhancement:
- Additional detection patterns
- Support for more platforms
- Integration with SIEM systems
- Machine learning-based anomaly detection
- Real-time monitoring capabilities
