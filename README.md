# Forensic-scripting-007

Read-only macOS forensic helper scripts for bug bounty evidence packets.

## Scripts

- `atlas_submission_capture.sh` builds a reviewer-friendly app comparison packet from a CSV manifest. It recursively inventories suspect and baseline app bundles, captures code-signing/notarization output, TCC rows, recent `tccd` logs, process state, optional PCAPs, terminal context, login history, deleted/Codex-related shell-history hits, hashes, and an optional zip archive.
- `scripts/credential_artifact_scanner.py` opens a copied TCC SQLite database read-only and exports high-risk Atlas/OpenAI/OwlBridge privacy permission hits to TSV for fast reviewer triage.
- `scripts/modification_timeline_scanner.py` builds a static modification timeline TSV for one or more evidence paths without executing target binaries.
- `recursive_macos_volume_verify.sh` recursively inventories a mounted macOS volume, folder, app bundle, package, or evidence directory. It hashes and statically verifies code-like files without executing target code.

## Quick start

```bash
cat > manifest.csv <<'CSV'
name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob
Atlas,/Applications/ChatGPT Atlas.app,/Applications/ChatGPT Atlas Fresh.app,ChatGPT Atlas,,
CSV

./atlas_submission_capture.sh manifest.csv ./results --pcap-duration 0
./recursive_macos_volume_verify.sh --out-base ./results --case atlas_recursive "/Applications/ChatGPT Atlas.app"
python3 scripts/credential_artifact_scanner.py --target ./results/tcc_snapshot.db --output ./results/credential_triage_hits.tsv
python3 scripts/modification_timeline_scanner.py --target "/Applications/ChatGPT Atlas.app" --output ./results/modification_timeline.tsv --hash
```

Both scripts are intentionally conservative: no `sudo`, no bundle mutation, no quarantine stripping, and no execution of suspect binaries.

## Resources

- [Codex & Copilot Guide](CODEX_COPILOT_GUIDE.md) covers GitHub Copilot signup, IDE/CLI setup, educational access, official docs, and common authentication troubleshooting.
