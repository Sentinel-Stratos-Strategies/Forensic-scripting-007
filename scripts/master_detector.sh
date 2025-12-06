#!/bin/bash
#
# Master Detection Script for LLM/AI Forensics
# This script runs all detection methods and generates a comprehensive report.
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Output directory
OUTPUT_DIR="./forensic_reports_$(date +%Y%m%d_%H%M%S)"

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     LLM/AI FORENSIC DETECTION SUITE                          ║${NC}"
echo -e "${GREEN}║     Creative Forensics & Detection Framework                  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] Not running as root. Some checks will be limited.${NC}"
    echo -e "${YELLOW}[!] For full analysis, run with: sudo $0${NC}"
    echo ""
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo -e "[*] Output directory: $OUTPUT_DIR"
echo ""

# Function to run a detector
run_detector() {
    local name=$1
    local script=$2
    local args=$3
    
    echo -e "${GREEN}[*] Running $name...${NC}"
    echo -e "    Script: $script"
    echo "----------------------------------------"
    
    if [ -f "$script" ]; then
        python3 "$script" $args 2>&1 | tee "$OUTPUT_DIR/${name}_output.txt"
        
        # Move JSON reports to output directory
        for json_file in *_report.json; do
            if [ -f "$json_file" ]; then
                mv "$json_file" "$OUTPUT_DIR/"
            fi
        done
        
        echo ""
    else
        echo -e "${RED}[!] Script not found: $script${NC}"
        echo ""
    fi
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run all detectors
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Starting Forensic Scan${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# 1. Anomaly Detection
run_detector "Anomaly_Detection" "$SCRIPT_DIR/anomaly_detector.py"

# 2. Signature Detection
run_detector "Signature_Detection" "$SCRIPT_DIR/signature_detector.py"

# 3. Behavioral Analysis
run_detector "Behavioral_Analysis" "$SCRIPT_DIR/behavioral_analyzer.py" "-d 5"

# 4. Log Analysis
run_detector "Log_Analysis" "$SCRIPT_DIR/log_analyzer.py"

# 5. Credential & Tracker Artifact Scan
run_detector "Credential_Artifact_Scan" "$SCRIPT_DIR/credential_artifact_scanner.py"

# Generate summary report
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Generating Summary Report${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

SUMMARY_FILE="$OUTPUT_DIR/SUMMARY_REPORT.txt"

{
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     LLM/AI FORENSIC DETECTION - SUMMARY REPORT               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Scan Date: $(date)"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "DETECTION RESULTS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    # Count findings from each report
    for json_file in "$OUTPUT_DIR"/*_report.json; do
        if [ -f "$json_file" ]; then
            filename=$(basename "$json_file")
            echo "File: $filename"
            
            # Simple JSON parsing (count non-empty arrays/objects)
            findings=$(grep -o '"type"' "$json_file" | wc -l)
            echo "  Findings: $findings"
            echo ""
        fi
    done
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "RECOMMENDATIONS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "1. Review all JSON reports in the output directory"
    echo "2. Investigate processes with multiple red flags"
    echo "3. Check for unauthorized model files or API usage"
    echo "4. Verify log integrity and check for tampering"
    echo "5. Monitor network traffic for suspicious API calls"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "NEXT STEPS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "- Use 'htop' to monitor suspicious processes in real-time"
    echo "- Use 'wireshark' or 'tcpdump' for network traffic analysis"
    echo "- Use 'strace' with root privileges for detailed syscall monitoring"
    echo "- Check /proc/<pid>/ directories for detailed process info"
    echo "- Review system logs in /var/log/ for additional evidence"
    echo ""
    
} > "$SUMMARY_FILE"

cat "$SUMMARY_FILE"

echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Scan Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "[+] All reports saved to: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "[+] Summary report: ${YELLOW}$OUTPUT_DIR/SUMMARY_REPORT.txt${NC}"
echo ""
echo -e "${GREEN}Thank you for using the LLM/AI Forensic Detection Suite!${NC}"
echo ""
