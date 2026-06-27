# Forensic-scripting-007

Read-only macOS forensic helper scripts for bug bounty evidence packets.

## Scripts

- `run_forensic_suite.sh` creates a local `.venv`, installs `requirements.txt`, and runs the detector suite plus recursive verifier. By default it reads `/Volumes/Storage` and writes timestamped output under `/Volumes/Ellis`.
- `scripts/master_detector.sh` runs the original LLM/AI detector scripts and can also call the recursive macOS volume verifier for a mounted evidence volume.
- `atlas_submission_capture.sh` builds a reviewer-friendly app comparison packet from a CSV manifest. It recursively inventories suspect and baseline app bundles, captures code-signing/notarization output, TCC rows, recent `tccd` logs, process state, optional PCAPs, terminal context, login history, per-case Truth Scanner/Codex audit hits, deleted-Codex shell-history filters, readable Trash path indicators, hashes, and an optional zip archive.
- `scripts/credential_artifact_scanner.py` opens a copied TCC SQLite database read-only and exports high-risk Atlas/OpenAI/OwlBridge privacy permission hits to TSV for fast reviewer triage.
- `scripts/modification_timeline_scanner.py` builds a static modification timeline TSV for one or more evidence paths without executing target binaries.
- `recursive_macos_volume_verify.sh` recursively inventories a mounted macOS volume, folder, app bundle, package, or evidence directory. It hashes and statically verifies code-like files without executing target code.

## Quick start

```bash
./run_forensic_suite.sh --input /Volumes/Storage --output /Volumes/Ellis --case atlas_storage --hash-mode all --max-text-mb 16

cat > manifest.csv <<'CSV'
name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob
Atlas,/Applications/ChatGPT Atlas.app,/Applications/ChatGPT Atlas Fresh.app,ChatGPT Atlas,,
CSV

./atlas_submission_capture.sh manifest.csv ./results --pcap-duration 0
./recursive_macos_volume_verify.sh --out-base ./results --case atlas_recursive "/Applications/ChatGPT Atlas.app"
python3 scripts/credential_artifact_scanner.py --target ./results/tcc_snapshot.db --output ./results/credential_triage_hits.tsv
python3 scripts/modification_timeline_scanner.py --target "/Applications/ChatGPT Atlas.app" --output ./results/modification_timeline.tsv --hash
```

The suite is intentionally conservative: no bundle mutation, no quarantine stripping, and no execution of suspect binaries. Production recursive runs are intentionally heavy: they create directory-grouped object ledgers, code verification tables, parse/codesign detail files, bundle/package/container checks, keyword scans, and hash manifests. On large evidence volumes, `/Volumes/Ellis` output can be tens of gigabytes. Some live captures, TCC paths, and packet capture workflows may require elevated permissions, but the recursive verifier and static app inventory remain read-only.

Per-case capture output includes `login_and_truth_scanner_audit/` with shell-history hits for Codex, Truth Scanner, Atlas/OpenAI, PCAP, deletion, and Trash indicators. Review `*.deleted_codex.filtered.txt` files and `trash_codex_paths.txt` when checking for deleted Codex artifacts or related cleanup commands.

## Local Safety

Secrets and local evidence are intentionally ignored. Do not force-add `.env`, `.env.*`, archives, generated evidence packets, local virtual environments, or nested working copies.
