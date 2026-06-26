# Technical Details

## Detection Mechanisms

This document provides technical details about how each detection method works.

**Offline by design:** All detectors execute locally without calling hosted APIs. Any references to API keys or provider domains are used strictly as indicators during scanning, not as dependencies. For optional local-only model helpers to interpret results, see [LOCAL_LLM_OPTIONS](LOCAL_LLM_OPTIONS.md).

## Anomaly Detector

### Process Name Analysis

**Method**: String matching against process names and command lines

**Indicators Searched**:
```python
llm_indicators = [
    'transformer', 'pytorch', 'tensorflow', 'huggingface',
    'llama', 'gpt', 'bert', 'model', 'inference',
    'tokenizer', 'embedding', 'neural', 'cuda', 'gpu'
]
```

**Implementation**: Uses `psutil.process_iter()` to enumerate all processes and checks:
- `proc.name()` - Process executable name
- `proc.cmdline()` - Full command line with arguments

### Resource Usage Analysis

**Memory Threshold**: 1GB (1024 * 1024 * 1024 bytes)
- Checks `proc.memory_info().rss` (Resident Set Size)
- Calculates memory percentage with `proc.memory_percent()`

**CPU Threshold**: 50%
- Uses `proc.cpu_percent(interval=0.1)` for point-in-time measurement
- Short interval to avoid blocking

### Network Connection Analysis

**Method**: Examines established network connections

**Implementation**:
- Uses `proc.connections(kind='inet')` 
- Checks for connections with remote addresses
- Records: IP, port, and connection status

**Suspicious Domains** (for future DNS resolution):
- openai.com, anthropic.com, huggingface.co
- replicate.com, cohere.ai, ai21.com

### Process Tree Analysis

**Parent-Child Relationships**:
- Checks if process parent is shell (bash, sh, python, node)
- Flags if child process has LLM indicators
- Detects processes with >10 children (worker pools)

## Signature Detector

### Command Line Signatures

**Regex Patterns**:
```python
patterns = [
    r'python.*model.*\.py',           # Python model scripts
    r'.*inference.*server',            # Inference servers
    r'.*api.*server.*\-\-model',       # API servers with model flag
    r'uvicorn.*main:app',              # Uvicorn ASGI server
    r'flask.*run.*model',              # Flask model servers
    r'serve.*\-\-model\-path',         # Serving frameworks
]
```

**Data Source**: `ps aux` command output

### Environment Variable Detection

**Location**: `/proc/<pid>/environ`

**Target Variables**:
- `CUDA_VISIBLE_DEVICES` - GPU device selection
- `TRANSFORMERS_CACHE` - Hugging Face cache location
- `HF_HOME` - Hugging Face home directory
- `TORCH_HOME` - PyTorch home directory
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` - API credentials

**Implementation**:
- Reads raw environ file (null-terminated strings)
- Parses key=value pairs
- Records processes with matching environment variables

### File Signature Detection

**Open Files**: Uses `lsof -n` command

**File Extensions**:
- `.pt`, `.pth` - PyTorch models
- `.pb` - TensorFlow Protocol Buffers
- `.h5` - Keras/TensorFlow HDF5 models
- `.onnx` - ONNX format models
- `config.json`, `tokenizer.json` - Model configurations

**Directory Scan Locations**:
- `~/.cache/huggingface` - Hugging Face models
- `~/.cache/torch` - PyTorch models
- `~/.local/share/` - User data
- `/tmp`, `/var/tmp` - Temporary files
- `/opt` - Optional software

**Optimization**:
- Maximum depth: 3 levels
- Minimum file size: 1MB (likely models)
- Only reports files matching signatures

### Port Detection

**Suspicious Ports** (common API servers):
- 8000 - Common Python API server
- 8080 - Alternative HTTP port
- 5000 - Flask default
- 7860 - Gradio default
- 11434 - Ollama default

**Tools Used**:
- Primary: `netstat -tlnp`
- Fallback: `ss -tlnp`

## Behavioral Analyzer

### System Call Monitoring

**Tool**: `strace` (requires root)

**Command**: `strace -c -p <pid>` (count mode)

**Suspicious Syscalls**:
- `mmap` - Memory mapping (model loading)
- `mprotect` - Memory protection changes
- `brk` - Heap expansion
- `futex` - Fast user-space mutex (thread sync)
- `sched_setaffinity` - CPU affinity
- `openat` - File operations

**Threshold**: >100 calls per syscall type

**Duration**: 5-10 seconds per process

### Memory Behavior Analysis

**Data Source**: `/proc/<pid>/maps`

**Detection**:
- Counts anonymous memory regions `[anon]`
- Flags regions >100MB (model data)
- Calculates total anonymous memory

**Why It Matters**: LLMs load model weights into large contiguous memory regions

### Thread Analysis

**Data Source**: `/proc/<pid>/status`

**Pattern**: `Threads: <count>`

**Threshold**: >10 threads

**Reasoning**: Parallel inference often uses thread pools

### File Access Monitoring

**Tool**: `strace -e trace=open,openat,read,write -p <pid>`

**Duration**: 5-10 seconds

**Patterns Searched**:
```python
patterns = [
    r'\.pt$', r'\.pth$',    # PyTorch
    r'\.pb$', r'\.h5$',      # TensorFlow
    r'\.onnx$',              # ONNX
    r'model', r'checkpoint', # Generic
    r'config\.json',         # Config files
    r'tokenizer'             # Tokenizers
]
```

## Log Analyzer

### Log Integrity Checks

**Methods**:

1. **Modification Time**
   - Checks `os.stat(file).st_mtime`
   - Flags files modified in last 5 minutes

2. **File Size**
   - Checks for empty log files (size = 0)
   - Suspicious if system has been running

3. **Permissions**
   - Checks file mode with `oct(stat.st_mode)`
   - Flags 777 permissions (world-writable)

### LLM Indicator Search

**Log Files Scanned**:
- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/auth.log`
- `/var/log/daemon.log`
- `/var/log/kern.log`

**Search Patterns**:
```python
patterns = [
    r'cuda|gpu|nvidia',                    # GPU usage
    r'torch|pytorch|tensorflow',           # Frameworks
    r'huggingface|transformers',           # HF libraries
    r'model.*load|inference|prediction',   # ML operations
    r'api.*key|token.*auth',               # Authentication
    r'openai|anthropic|cohere',            # AI services
]
```

**Optimization**: Scans first 10,000 lines per file

### Tampering Detection

**Command Patterns**:
```python
indicators = [
    r'log.*deleted|removed|cleared',  # Direct log deletion
    r'journalctl.*clear|vacuum',      # Journal manipulation
    r'rm.*\.log',                     # Log file removal
    r'truncate.*log',                 # Log truncation
    r'>/var/log/',                    # Redirection to logs
]
```

**Search Locations**:
- System logs
- `~/.bash_history`
- `~/.zsh_history`
- `/root/.bash_history`

### Timestamp Gap Analysis

**Method**:
1. Extract timestamps from log lines
2. Parse timestamps (multiple formats)
3. Look for gaps >1 hour (simplified)

**Timestamp Formats**:
- ISO 8601: `YYYY-MM-DDTHH:MM:SS`
- Syslog: `Mon DD HH:MM:SS`

**Note**: Current implementation flags for manual review

### Systemd Journal Analysis

**Tool**: `journalctl`

**Command**: `journalctl --since '24 hours ago' -g <pattern> -n 10`

**Patterns**: cuda, gpu, torch, model, inference

**Records**: Pattern, match count, sample entry

## Persistence Detector

### Cron Analysis

**Targets**:
- `/etc/crontab`, `/etc/cron.d`, `/etc/cron.*`
- `/var/spool/cron` and `/var/spool/cron/crontabs`

**Detection Logic**:
- Regex match for LLM keywords in scheduled commands
- Flags API key exports or invocations hitting AI providers
- Highlights curl/wget calls to `openai`, `anthropic`, `huggingface`, `cohere`, `ollama`, `replicate`, `hf.space`

### Systemd Unit Inspection

**Files Scanned**: `*.service` files in `/etc/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`

**Checks**:
- `Description=` fields containing LLM indicators
- `ExecStart=` commands referencing models, weights, tokens, or API keys

### Shell Profile Hooks

**Files Scanned**: `~/.bashrc`, `~/.profile`, `~/.zshrc`, `/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/zshrc`

**Indicators**:
- Exported AI API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HUGGINGFACEHUB_API_TOKEN`, `COHERE_API_KEY`, `AI21_API_KEY`)
- Aliases or commands that launch model servers (e.g., `ollama`, `python -m ... serve`)

## Data Flow

### Anomaly Detector

```
psutil.process_iter()
    ↓
For each process:
    ↓
    ├─→ Check name/cmdline for LLM indicators
    ├─→ Check memory usage > 1GB
    ├─→ Check CPU usage > 50%
    ├─→ Check network connections
    └─→ Check process tree relationships
    ↓
Aggregate findings by type
    ↓
Generate console report + JSON export
```

### Signature Detector

```
Multiple data sources:
    ↓
    ├─→ ps aux → Command line matching
    ├─→ /proc/*/environ → Environment variables
    ├─→ lsof → Open files
    ├─→ netstat/ss → Network ports
    └─→ File system → Model files in cache
    ↓
Pattern matching with regex
    ↓
Aggregate findings by type
    ↓
Generate console report + JSON export
```

### Behavioral Analyzer

```
Get high-memory processes (ps aux --sort=-%mem)
    ↓
For each target process:
    ↓
    ├─→ Read /proc/<pid>/maps → Memory regions
    ├─→ Read /proc/<pid>/status → Thread count
    ├─→ Run strace -c → Syscall counts
    └─→ Run strace -e trace=file → File access
    ↓
Analyze patterns:
    ├─→ Large anonymous memory?
    ├─→ High thread count?
    ├─→ Suspicious syscalls?
    └─→ Model file access?
    ↓
Generate console report + JSON export
```

### Log Analyzer

```
For each log file:
    ↓
    ├─→ Check file metadata (mtime, size, perms)
    ├─→ Search for LLM patterns
    └─→ Search for tampering commands
    ↓
Scan bash history files
    ↓
Query systemd journal
    ↓
Aggregate findings by type
    ↓
Generate console report + JSON export
```

## Performance Considerations

### Anomaly Detector
- **Time**: 2-5 seconds for typical system
- **CPU**: Minimal (process enumeration)
- **Disk**: None

### Signature Detector
- **Time**: 10-30 seconds (depends on open files)
- **CPU**: Moderate (lsof can be slow)
- **Disk**: High if scanning cache directories

### Behavioral Analyzer
- **Time**: 5-10 seconds per process × 5 processes = 25-50 seconds
- **CPU**: High (strace overhead)
- **Disk**: Low
- **Requires**: Root access for full functionality

### Log Analyzer
- **Time**: 5-15 seconds (depends on log size)
- **CPU**: Low
- **Disk**: Moderate (reading log files)

## Security Implications

### Read-Only Operations
All scripts are **read-only**:
- No process termination
- No file modification
- No system configuration changes

### Information Disclosure
Reports may contain:
- Process command lines (including arguments)
- Environment variable values (may include API keys)
- File paths (system layout information)
- Network connections (IP addresses)

**Recommendation**: Store reports securely

### Privilege Requirements

**Without Root**:
- Basic process information
- Own user's processes
- Public log files

**With Root**:
- All process information
- All environment variables
- System logs
- Syscall tracing
- Complete file access information

### Evasion Techniques

Sophisticated actors can evade detection by:

1. **Process Renaming**: Use generic names
2. **No Obvious Indicators**: Avoid framework keywords
3. **Memory Obfuscation**: Use paging, compression
4. **Log Cleaning**: Remove evidence after use
5. **Legitimate Processes**: Inject into existing processes
6. **Network Tunneling**: Hide API calls in encrypted traffic

## Future Enhancements

Potential improvements:

1. **ML-Based Anomaly Detection**: Learn normal patterns
2. **Behavioral Baselines**: Compare against known good state
3. **Real-Time Monitoring**: Continuous scanning daemon
4. **SIEM Integration**: Export to security platforms
5. **Windows Support**: Adapt for Windows environments
6. **Container Detection**: Scan Docker/K8s environments
7. **Cloud API Monitoring**: Detect cloud-based AI usage
8. **Memory Forensics**: Analyze memory dumps
9. **DNS Analysis**: Resolve and categorize connections
10. **Signature Updates**: Maintain database of new patterns

## References

- `psutil` documentation: https://psutil.readthedocs.io/
- `/proc` filesystem: Linux kernel documentation
- `strace` manual: https://man7.org/linux/man-pages/man1/strace.1.html
- `lsof` manual: https://man7.org/linux/man-pages/man8/lsof.8.html
