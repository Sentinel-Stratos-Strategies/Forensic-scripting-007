# Forensic-scripting-007

A macOS-focused evidence collection script for app-integrity and privacy/TCC bug bounty submissions. It recursively inventories suspect and baseline `.app` bundles, captures trust metadata, records process/TCC/privacy-log support, stages PCAP evidence, and packages everything into a zip with SHA-256 manifests.

## What the script captures

- Suspect and baseline app metadata, hashes, `codesign`, and Gatekeeper (`spctl`) results.
- Recursive bundle inventory for nested apps, frameworks, XPC services, extensions, plists, dylibs, executable files, and provisioning profiles.
- Static artifact details including file type, stats, extended attributes, load commands, linked libraries, plist rendering, codesign metadata, and high-signal strings.
- Process snapshots for the configured app/process name.
- Current-user TCC database rows for discovered bundle identifiers.
- Recent privacy-relevant unified logs, including `tccd` output where readable.
- Existing PCAPs matched by manifest glob and optional short live `tcpdump` capture when permissions allow it.
- Login/history audit files that surface logins, past use of Codex/Atlas/TCC/pcap-related commands, deletion commands, and readable Trash/path indicators for deleted Codex/Atlas artifacts.
- Optional triage target matrix searches for reviewer-defined indicators such as emails, phone numbers, MDM/DPEP terms, enrollment terms, disk image/seal language, or secret/token indicators while redacting credential-like values.
- Correlated `timeline_events.tsv` and `evidence.sqlite` outputs for mapping artifact timestamps, generated evidence, TCC/log outputs, PCAPs, and login/Codex audit files together.
- Run-level `summary.tsv`, `artifact_summary.tsv`, `findings.tsv`, `triage_hits.tsv`, `timeline_events.tsv`, `tool_status.tsv`, `evidence.sqlite`, `SHA256SUMS.txt`, and a zipped evidence packet.

## Safety boundaries

The script is designed to be evidence-preserving and reviewer-friendly:

- It does **not** execute suspect applications.
- It does **not** write into app bundles.
- It does **not** strip quarantine attributes.
- It does **not** require sudo, although macOS may require elevated permissions for live packet capture or protected logs.

## Manifest format

Create a CSV with this header:

```csv
name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob,interface,pcap_seconds
```

Only the first six columns are required; `interface` and `pcap_seconds` are optional.

Optional triage target matrix:

```csv
label,pattern,scope,severity,notes
email,[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,},run,medium,Find email-like indicators
phone,\+?[0-9][0-9 .()-]{7,}[0-9],run,medium,Find phone-like indicators
mdm_terms,MDM|DeviceEnrollment|profiles|configuration profile,run,high,Enrollment/configuration language
disk_seal,seal|sealed|disk image|dmg|hdiutil|apfs,run,high,Disk image or seal manipulation language
github_pat,github_pat_|ghp_,run,critical,Redacted proof of GitHub token-like indicators
```

Example:

```csv
name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob,interface,pcap_seconds
Atlas,/Applications/ChatGPT Atlas.app,/Applications/ChatGPT Atlas Fresh.app,"ChatGPT Atlas","/Volumes/Evidence/pcaps/*Atlas*.pcap","/Volumes/Evidence/extra/*",en0,30
Codex,/Applications/Codex.app,/Applications/Codex Fresh.app,Codex,,,,
```

## Usage

```bash
chmod +x atlas_submission_capture.sh
./atlas_submission_capture.sh --self-test
./atlas_submission_capture.sh manifest.csv /Volumes/Evidence triage_targets.csv
```

The output folder will be named like:

```text
/Volumes/Evidence/atlas_submission_capture_20260626T150000Z/
/Volumes/Evidence/atlas_submission_capture_20260626T150000Z.zip
```

## Reviewer workflow

1. Open `findings.tsv` for high/medium issues.
2. Compare suspect vs. baseline rows in `summary.tsv`.
3. Review `codesign_bundle.txt`, `spctl_bundle.txt`, and `outer_executable/` for each role.
4. Use `artifact_summary.tsv` and `*_inventory/inventory_paths.txt` to prove recursive search coverage.
5. Review `process/`, `tcc/`, `logs/`, `pcaps/`, and `login_and_codex_audit/` for runtime and privacy support.
6. Check `tool_status.tsv` so unavailable macOS-only tooling is explicit instead of silent.
7. Review `triage_hits.tsv`; secret/token-like rows are redacted by design and include line hashes for proof without exposing credentials.
8. Use `timeline_events.tsv` and `evidence.sqlite` to correlate filesystem, TCC/log, PCAP, login/Codex audit, and generated-evidence timestamps into event clusters.
9. Verify `SHA256SUMS.txt` and the `.zip.sha256` before submitting.

## Requirements

Core macOS tools: `bash`, `python3`, `find`, `file`, `stat`, `xattr`, `strings`, `codesign`, `spctl`, `plutil`, `otool`, `log`, `sqlite3`, `zip`, and optionally `tcpdump`. Missing optional or macOS-only tools are recorded in `tool_status.tsv` or per-artifact stderr/unavailable files so reviewers can distinguish environment limits from missing evidence.
