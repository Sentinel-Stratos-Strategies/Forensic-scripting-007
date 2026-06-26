#!/usr/bin/env python3
"""
Log Analysis Script for LLM/AI Detection and Log Manipulation Detection
This script analyzes system logs for signs of LLM activity and log tampering.
"""

import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


class LogAnalyzer:
    # Configuration constants
    MAX_LOG_LINES_TO_SCAN = 10000  # Limit lines scanned per file for performance
    
    def __init__(self):
        self.findings = []
        
        # Log files to analyze
        self.log_files = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/auth.log',
            '/var/log/daemon.log',
            '/var/log/kern.log',
        ]
        
        # LLM/AI related patterns in logs
        self.llm_patterns = [
            r'cuda|gpu|nvidia',
            r'torch|pytorch|tensorflow',
            r'huggingface|transformers',
            r'model.*load|inference|prediction',
            r'api.*key|token.*auth',
            r'openai|anthropic|cohere',
        ]
        
        # Log manipulation indicators
        self.tampering_indicators = [
            r'log.*deleted|removed|cleared',
            r'journalctl.*clear|vacuum',
            r'rm.*\.log',
            r'truncate.*log',
            r'>/var/log/',  # Redirection to log files
        ]

    def check_log_integrity(self, log_file):
        """Check for signs of log tampering"""
        issues = []
        
        try:
            if not os.path.exists(log_file):
                return issues
            
            # Check file metadata
            stat_info = os.stat(log_file)
            mtime = datetime.fromtimestamp(stat_info.st_mtime)
            ctime = datetime.fromtimestamp(stat_info.st_ctime)
            
            # Check if log file was recently modified
            now = datetime.now()
            if (now - mtime).total_seconds() < 300:  # Modified in last 5 minutes
                issues.append({
                    'type': 'recent_modification',
                    'file': log_file,
                    'mtime': mtime.isoformat(),
                    'seconds_ago': (now - mtime).total_seconds()
                })
            
            # Check for suspicious file size
            if stat_info.st_size == 0:
                issues.append({
                    'type': 'empty_log',
                    'file': log_file,
                    'size': 0
                })
            
            # Check permissions
            mode = oct(stat_info.st_mode)[-3:]
            if mode == '777':
                issues.append({
                    'type': 'suspicious_permissions',
                    'file': log_file,
                    'permissions': mode
                })
            
        except PermissionError:
            pass
        except Exception as e:
            pass
        
        return issues

    def analyze_log_gaps(self, log_file):
        """Detect gaps in log timestamps (possible deletion)"""
        gaps = []
        
        try:
            if not os.path.exists(log_file):
                return gaps
            
            with open(log_file, 'r', errors='ignore') as f:
                lines = []
                for line in f:
                    lines.append(line)
                    if len(lines) >= 1000:
                        break
            
            # Parse timestamps and look for unusual gaps
            timestamps = []
            timestamp_patterns = [
                r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})',  # ISO format
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # syslog format
            ]
            
            for line in lines[:1000]:  # Sample first 1000 lines
                for pattern in timestamp_patterns:
                    match = re.search(pattern, line)
                    if match:
                        try:
                            ts_str = match.group(1)
                            # Simple timestamp extraction
                            timestamps.append(ts_str)
                            break
                        except Exception:
                            continue
            
            # Check for large gaps (>1 hour)
            if len(timestamps) > 1:
                # This is simplified; real analysis would parse timestamps properly
                gaps.append({
                    'type': 'timestamp_analysis',
                    'file': log_file,
                    'sample_count': len(timestamps),
                    'note': 'Manual review recommended for gap analysis'
                })
            
        except PermissionError:
            pass
        except Exception as e:
            pass
        
        return gaps

    def search_llm_indicators(self, log_file):
        """Search for LLM/AI related entries in logs"""
        matches = []
        
        try:
            if not os.path.exists(log_file):
                return matches
            
            with open(log_file, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern in self.llm_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append({
                                'file': log_file,
                                'line': line_num,
                                'pattern': pattern,
                                'content': line.strip()[:200]
                            })
                            break
                    
                    # Limit lines scanned for performance
                    if line_num > self.MAX_LOG_LINES_TO_SCAN:
                        break
            
        except PermissionError:
            pass
        except Exception as e:
            pass
        
        return matches

    def search_tampering_commands(self, log_file):
        """Search for log tampering commands in bash history and logs"""
        tampering = []
        
        try:
            if not os.path.exists(log_file):
                return tampering
            
            with open(log_file, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern in self.tampering_indicators:
                        if re.search(pattern, line, re.IGNORECASE):
                            tampering.append({
                                'file': log_file,
                                'line': line_num,
                                'indicator': pattern,
                                'content': line.strip()[:200]
                            })
                            break
                    
                    if line_num > self.MAX_LOG_LINES_TO_SCAN:
                        break
            
        except PermissionError:
            pass
        except Exception as e:
            pass
        
        return tampering

    def analyze_bash_history(self):
        """Analyze bash history for suspicious commands"""
        history_files = [
            os.path.expanduser('~/.bash_history'),
            os.path.expanduser('~/.zsh_history'),
            '/root/.bash_history',
        ]
        
        suspicious_commands = []
        
        for history_file in history_files:
            try:
                if not os.path.exists(history_file):
                    continue
                
                with open(history_file, 'r', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Check for LLM indicators
                        for pattern in self.llm_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                suspicious_commands.append({
                                    'type': 'llm_command',
                                    'file': history_file,
                                    'line': line_num,
                                    'command': line.strip()[:200]
                                })
                                break
                        
                        # Check for tampering
                        for pattern in self.tampering_indicators:
                            if re.search(pattern, line, re.IGNORECASE):
                                suspicious_commands.append({
                                    'type': 'tampering_command',
                                    'file': history_file,
                                    'line': line_num,
                                    'command': line.strip()[:200]
                                })
                                break
                
            except PermissionError:
                continue
            except Exception as e:
                continue
        
        return suspicious_commands

    def analyze_systemd_journal(self):
        """Analyze systemd journal for LLM activity"""
        import subprocess
        
        journal_findings = []
        
        try:
            # Search for LLM-related entries in journalctl
            for pattern in ['cuda', 'gpu', 'torch', 'model', 'inference']:
                result = subprocess.run(
                    ['journalctl', '--since', '24 hours ago', '-g', pattern, '-n', '10'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 0:
                        journal_findings.append({
                            'pattern': pattern,
                            'match_count': len(lines),
                            'sample': lines[0][:200] if lines else ''
                        })
            
        except FileNotFoundError:
            pass  # journalctl not available
        except Exception as e:
            pass
        
        return journal_findings

    def scan_system(self):
        """Perform complete log analysis"""
        print(f"[*] Starting log analysis at {datetime.now()}")
        print("-" * 80)
        
        # Check log integrity
        print("[*] Checking log file integrity...")
        for log_file in self.log_files:
            integrity_issues = self.check_log_integrity(log_file)
            if integrity_issues:
                self.findings.extend(integrity_issues)
            
            gaps = self.analyze_log_gaps(log_file)
            if gaps:
                self.findings.extend(gaps)
        
        # Search for LLM indicators
        print("[*] Searching for LLM/AI indicators in logs...")
        for log_file in self.log_files:
            matches = self.search_llm_indicators(log_file)
            if matches:
                for match in matches[:10]:  # Limit per file
                    self.findings.append({
                        'type': 'llm_indicator',
                        **match
                    })
        
        # Search for tampering
        print("[*] Searching for log tampering indicators...")
        for log_file in self.log_files:
            tampering = self.search_tampering_commands(log_file)
            if tampering:
                for item in tampering[:10]:
                    self.findings.append({
                        'type': 'tampering_indicator',
                        **item
                    })
        
        # Analyze bash history
        print("[*] Analyzing command history...")
        history_findings = self.analyze_bash_history()
        self.findings.extend(history_findings)
        
        # Analyze systemd journal
        print("[*] Analyzing systemd journal...")
        journal_findings = self.analyze_systemd_journal()
        for finding in journal_findings:
            self.findings.append({
                'type': 'journal_entry',
                **finding
            })

    def generate_report(self):
        """Generate detailed report"""
        print("\n" + "=" * 80)
        print("LOG ANALYSIS REPORT")
        print("=" * 80)
        
        if not self.findings:
            print("[+] No suspicious log entries or tampering detected.")
            print("[*] Note: Some log files may require elevated privileges")
            return
        
        # Group by type
        findings_by_type = defaultdict(list)
        for finding in self.findings:
            finding_type = finding.get('type', 'unknown')
            findings_by_type[finding_type].append(finding)
        
        # Report integrity issues
        if findings_by_type['recent_modification']:
            print(f"\n[!] Found {len(findings_by_type['recent_modification'])} recently modified log file(s):")
            for item in findings_by_type['recent_modification']:
                print(f"    File: {item['file']}")
                print(f"    Modified: {item['seconds_ago']:.0f} seconds ago")
                print()
        
        if findings_by_type['empty_log']:
            print(f"\n[!] Found {len(findings_by_type['empty_log'])} empty log file(s):")
            for item in findings_by_type['empty_log']:
                print(f"    File: {item['file']}")
                print()
        
        if findings_by_type['suspicious_permissions']:
            print(f"\n[!] Found {len(findings_by_type['suspicious_permissions'])} file(s) with suspicious permissions:")
            for item in findings_by_type['suspicious_permissions']:
                print(f"    File: {item['file']}")
                print(f"    Permissions: {item['permissions']}")
                print()
        
        # Report LLM indicators
        if findings_by_type['llm_indicator']:
            print(f"\n[!] Found {len(findings_by_type['llm_indicator'])} LLM/AI indicator(s) in logs:")
            for item in findings_by_type['llm_indicator'][:10]:
                print(f"    File: {item['file']}:{item['line']}")
                print(f"    Pattern: {item['pattern']}")
                print(f"    Content: {item['content'][:100]}")
                print()
            if len(findings_by_type['llm_indicator']) > 10:
                print(f"    ... and {len(findings_by_type['llm_indicator']) - 10} more")
        
        # Report tampering
        if findings_by_type['tampering_indicator']:
            print(f"\n[!] Found {len(findings_by_type['tampering_indicator'])} tampering indicator(s):")
            for item in findings_by_type['tampering_indicator'][:10]:
                print(f"    File: {item['file']}:{item['line']}")
                print(f"    Indicator: {item['indicator']}")
                print(f"    Content: {item['content'][:100]}")
                print()
        
        # Report command history
        if findings_by_type['llm_command']:
            print(f"\n[!] Found {len(findings_by_type['llm_command'])} LLM-related command(s) in history:")
            for item in findings_by_type['llm_command'][:10]:
                print(f"    File: {item['file']}")
                print(f"    Command: {item['command'][:100]}")
                print()
        
        if findings_by_type['tampering_command']:
            print(f"\n[!] Found {len(findings_by_type['tampering_command'])} tampering command(s) in history:")
            for item in findings_by_type['tampering_command'][:10]:
                print(f"    File: {item['file']}")
                print(f"    Command: {item['command'][:100]}")
                print()
        
        # Report journal findings
        if findings_by_type['journal_entry']:
            print(f"\n[!] Found {len(findings_by_type['journal_entry'])} journal match(es):")
            for item in findings_by_type['journal_entry'][:5]:
                print(f"    Pattern: {item['pattern']}")
                print(f"    Matches: {item['match_count']}")
                print()
        
        if findings_by_type['timestamp_analysis']:
            print(f"\n[!] Found {len(findings_by_type['timestamp_analysis'])} log file(s) with timestamp gaps:")
            for item in findings_by_type['timestamp_analysis'][:10]:
                print(f"    File: {item['file']}")
                print(f"    Samples: {item['sample_count']}")
                print(f"    Note: {item['note']}")
                print()
        
        print("\n" + "=" * 80)

    def export_json(self, filename='log_analysis_report.json'):
        """Export findings to JSON"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"[+] Report exported to {filename}")


def main():
    analyzer = LogAnalyzer()
    analyzer.scan_system()
    analyzer.generate_report()
    analyzer.export_json()


if __name__ == '__main__':
    main()
