# Forensic Scripting 007: LLM/AI Detection Suite

## CREATIVE FORENSICS & LLM DETECTION

Think outside the box! AI/LLMs can mimic system processes, hide in daemons, or manipulate logs. This suite provides unconventional forensic methods for detecting hidden AI/LLM processes including anomaly detection, signature-based detection, and behavioral analysis.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)

## 🎯 Overview

This comprehensive forensic detection suite helps identify hidden AI/LLM processes that might be:
- Masquerading as legitimate system processes
- Running unauthorized inference servers
- Using system resources covertly
- Manipulating system logs to hide their presence
- Communicating with external AI/LLM APIs (optional; detectors themselves run offline)

## 🔍 Detection Methods

### 1. **Anomaly Detection** (`anomaly_detector.py`)
Identifies processes with suspicious characteristics:
- LLM/AI-related names or command arguments
- Unusually high memory usage (>1GB)
- High CPU consumption (>50%)
- Suspicious network connections to AI services
- Anomalous parent-child process relationships

### 2. **Signature-Based Detection** (`signature_detector.py`)
Pattern matching for known LLM frameworks and indicators:
- Process command signatures (PyTorch, TensorFlow, Hugging Face)
- Environment variables indicating AI usage
- Open model files (.pt, .pb, .h5, .onnx)
- Processes listening on common API ports
- Model files in cache directories

### 3. **Behavioral Analysis** (`behavioral_analyzer.py`)
Real-time monitoring of process behavior:
- System call patterns (mmap, futex, mprotect)
- Large anonymous memory regions (model loading)
- High thread counts (parallel inference)
- File access patterns for model files
- Memory allocation behavior

### 4. **Log Analysis** (`log_analyzer.py`)
Detects AI activity and log tampering:
- LLM/AI indicators in system logs
- Log file integrity checks
- Evidence of log manipulation
- Suspicious commands in bash history
- Timestamp gaps and anomalies

### 5. **Persistence Detection** (`persistence_detector.py`)
Uncovers stealthy startup mechanisms that can relaunch hidden AI workloads:
- Cron jobs pointing to model servers or API calls
- systemd unit files with LLM/AI keywords or API keys
- Shell profile hooks exporting AI credentials or aliases
- Curl/wget beacons to public AI endpoints

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007.git
cd Forensic-scripting-007

# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh scripts/*.py
```

### Download without git

Prefer a one-time download instead of cloning? Grab the latest ZIP directly from GitHub and unpack it:

```bash
# Download the current main branch as a ZIP
wget https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007/archive/refs/heads/main.zip -O forensic-suite.zip

# Unpack and enter the directory
unzip forensic-suite.zip
cd Forensic-scripting-007-main
```

For versioned bundles, use the Releases page and pick a tagged archive instead:
https://github.com/Sentinel-Stratos-Strategies/Forensic-scripting-007/releases

### Basic Usage

Run the master detection script for a comprehensive scan:

```bash
# Basic scan
./scripts/master_detector.sh

# Full scan with root privileges (recommended)
sudo ./scripts/master_detector.sh
```

Or run individual detectors:

```bash
# Anomaly detection
python3 scripts/anomaly_detector.py

# Signature detection
python3 scripts/signature_detector.py

# Behavioral analysis (benefits from root access)
sudo python3 scripts/behavioral_analyzer.py

# Log analysis
sudo python3 scripts/log_analyzer.py
```

### Offline and API-free operation

All detectors run locally and do not require API keys or internet access. If you want a local LLM to summarize findings, pick one of the offline-friendly models listed in [docs/LOCAL_LLM_OPTIONS.md](docs/LOCAL_LLM_OPTIONS.md) and pipe the reports into it. No cloud calls are needed.

## 📊 Output

Each detector generates:
1. **Console Report**: Formatted, human-readable findings
2. **JSON Report**: Machine-readable data for further analysis
3. **Summary Report**: Aggregated findings with recommendations (master script)

Example output structure:
```
forensic_reports_20251205_190000/
├── SUMMARY_REPORT.txt
├── Anomaly_Detection_output.txt
├── anomaly_report.json
├── Signature_Detection_output.txt
├── signature_report.json
├── Behavioral_Analysis_output.txt
├── behavioral_report.json
├── Log_Analysis_output.txt
└── log_analysis_report.json
```

## 🛠️ Tools Used

The suite integrates with common forensic and system tools:

- **htop** - Interactive process monitoring
- **ps/top** - Process listing and monitoring
- **lsof** - List open files
- **strace** - System call tracing
- **netstat/ss** - Network connection monitoring
- **grep** - Pattern matching in logs
- **Wireshark/tcpdump** - Network traffic analysis (suggested for follow-up)

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md) - Detailed setup instructions
- [Usage Guide](docs/USAGE.md) - Comprehensive usage examples and best practices

## 🔐 Security Considerations

- Scripts are **read-only** and do not modify system state
- Some features require **root/sudo** access for deep inspection
- Reports may contain **sensitive information** (paths, command lines)
- Use only in **authorized environments**
- Review scripts before running with elevated privileges

## 🎯 Use Cases

- **Security Audits**: Detect unauthorized AI/LLM usage
- **Compliance Monitoring**: Ensure AI usage policies are followed
- **Incident Response**: Investigate suspicious AI-related activity
- **Research**: Study AI/LLM process behavior patterns
- **System Administration**: Monitor resource usage by AI applications

## 🔬 Detection Indicators

The suite looks for various indicators:

**Process Indicators:**
- Keywords: `transformer`, `pytorch`, `tensorflow`, `llama`, `gpt`, `bert`
- High resource consumption
- Multiple threads (parallel inference)

**File Indicators:**
- Model files: `.pt`, `.pth`, `.pb`, `.h5`, `.onnx`
- Configuration: `config.json`, `tokenizer.json`
- Cache directories: `~/.cache/huggingface`, `~/.cache/torch`

**Network Indicators:**
- Connections to AI APIs: OpenAI, Anthropic, Hugging Face
- Common ports: 8000, 8080, 5000, 7860, 11434

**Environment Indicators:**
- Variables: `CUDA_VISIBLE_DEVICES`, `TRANSFORMERS_CACHE`, `HF_HOME`
- API keys: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`

## ⚠️ Limitations

- **False Positives**: Legitimate AI/ML applications will be flagged
- **Evasion Possible**: Sophisticated actors can rename processes and hide signatures
- **Performance Impact**: Some scans can be resource-intensive
- **Platform Specific**: Some features are Linux-specific
- **Requires Privileges**: Many checks need root access for full effectiveness

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:
- Additional detection patterns
- Support for more platforms (Windows native)
- Integration with SIEM systems
- Machine learning-based anomaly detection
- Real-time monitoring capabilities

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by creative forensics and unconventional detection methods
- Built for the security and research community
- Designed to help organizations monitor and secure AI usage

## 📧 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Review the documentation in `/docs`
- Check the script source code for detailed comments

## 🔗 Related Tools

Consider using these tools alongside the suite:
- **htop** - Real-time process monitoring
- **Wireshark** - Network traffic analysis
- **osquery** - SQL-powered system instrumentation
- **Sysdig** - System call monitoring and troubleshooting
- **Falco** - Runtime security and threat detection

---

**Remember**: Use responsibly and only in authorized environments. This tool is for security research and authorized system administration only. 
