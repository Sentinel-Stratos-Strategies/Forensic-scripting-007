# 007 / Genesis OS / Hydrate Go Plan

Generated: 2026-06-28

## Product Shape

```text
Genesis OS
  polished product and workflow shell
        |
        v
007 Backend
  capture engine and normalized security database
        |
        v
Hydrate / Atlas / Chrome / Codex / MobileSync / TCC / PCAP collectors
```

007 is the private-eye backend. Genesis OS is the user-facing product. Hydrate is the iPhone/iPad evidence intake lane.

## Repos And Folders

- 007 backend: `/Users/fresh/Forensic_007`
- Genesis OS product shell: `/Users/fresh/The_Genesis_Method/the-genesis-method`
- Hydrate mobile lane: `/Users/fresh/Hydrate`
- Recovered Hydrate source material: `/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools`

## Imported Now

Hydrate iOS shell app:

- `/Users/fresh/Hydrate/HydrateInspector`

Hydrate collector scripts staged into 007:

- `scripts/hydrate/iphone_host_snapshot.py`
- `scripts/hydrate/app_watch.py`
- `scripts/hydrate/bundle_binary_inventory.py`
- `scripts/hydrate/cache_forensic_scan.py`
- `scripts/hydrate/icloud_local_inventory.py`
- `scripts/hydrate/recent_artifact_window.py`
- `scripts/hydrate/forensic_console_mcp.py`

## 007 Database Layers

### Layer 1 - Core 3NF Case Database

Purpose: durable normalized evidence.

Tables:

- `cases`
- `runs`
- `devices`
- `apps`
- `artifacts`
- `files`
- `hashes`
- `tcc_rows`
- `pcap_flows`
- `process_samples`
- `network_samples`
- `app_bundles`
- `codesign_records`
- `entitlements`
- `mobile_sync_items`
- `ios_host_events`
- `cache_hits`
- `claims`
- `claim_evidence`
- `excluded_claims`
- `chain_of_custody`

### Layer 2 - Graph / Correlation Database

Purpose: relationship queries without duplicating raw files.

Edges:

- device -> artifact
- app -> process
- app -> TCC row
- app -> network flow
- file -> hash
- claim -> evidence
- Hydrate export -> MobileSync backup
- Atlas/Chrome/Codex -> helpers/caches/permissions

### Layer 3 - Output / Report Cache Database

Purpose: fast dashboards and exports.

Rows:

- dashboard cards
- timeline rows
- chart series
- reviewer packet sections
- AI narrative source references
- export manifests

Large artifacts stay on disk under `/Volumes/Ellis`; SQLite stores hashes, metadata, paths, and relationships.

## Go Pipeline

1. Case init and scope guard.
2. Toolchain validation.
3. TCC pre-snapshot.
4. PCAP start.
5. Launch selected Atlas / Chrome / Codex apps.
6. App watcher samples process/socket/file/log activity.
7. TCC post-launch snapshot.
8. Bundle/Mach-O inventory for Atlas, Chrome, Codex, and staged clones.
9. Cache forensic scan for Atlas/Chrome/Codex/OpenAI/TCC/MobileSync indicators.
10. iPhone host snapshot and MobileSync backup inventory.
11. Hydrate iOS report import when available.
12. Recursive macOS verifier over `/Volumes/Storage` or selected evidence roots.
13. Canonical event normalization.
14. 3NF database load.
15. Graph edge build.
16. Claim matrix and excluded-claims update.
17. Reviewer README, timeline, packet summaries, and hash manifests.

## What The Output Looks Like

Each run should land under `/Volumes/Ellis/<case>_<timestamp>/` with:

- `CASE_CONTEXT.json`
- `RUN_LEDGER.jsonl`
- `TOOLCHAIN_LOCK.json`
- `tcc/`
- `pcap/`
- `app_watch/`
- `bundle_inventory/`
- `cache_scan/`
- `iphone_host_snapshot/`
- `mobilesync/`
- `hydrate_import/`
- `recursive_verify/`
- `canonical/CANONICAL_EVENTS.csv`
- `database/007_core.sqlite`
- `database/007_graph.sqlite`
- `database/007_outputs.sqlite`
- `CLAIM_MATRIX.csv`
- `EXCLUDED_CLAIMS.md`
- `REVIEWER_README.md`
- `HASH_MANIFEST.sha256`

## Run-Time Expectations

Small smoke test:

- 5 to 15 minutes.
- Limited source roots and no full-volume hashing.

Bug bounty focused pass:

- 45 minutes to 2 hours.
- TCC, PCAP, app launch, app watch, bundle inventory, cache scan, MobileSync index, targeted recursive verifier.

Full Ellis-grade pass:

- 2.5 to 6+ hours.
- Broad recursive scan, full hash mode, PCAP, repeated TCC samples, app launches, large MobileSync/source roots.
- Output can reasonably reach tens of gigabytes depending on source volume size and hash mode.

## Proof Boundary

This plan can produce a strong bug bounty package if the required artifacts are present in the source data. The package can directly prove:

- exact files, paths, hashes, timestamps, and xattrs.
- TCC rows and changes captured in database snapshots.
- app bundle signatures, entitlements, nested helpers, and Gatekeeper assessment.
- process/network activity observed during the capture window.
- PCAP flows and DNS/TLS endpoints captured during the run.
- MobileSync and Hydrate-imported mobile-side file inventories.
- correlations between app clones, support paths, permissions, caches, and timeline events.

The package should not claim rogue ABM/MDM control, preboot/cryptex intrusion, or third-party federation as proved unless the run captures direct supporting artifacts such as:

- configuration profile payloads.
- enrollment records or MDM server URLs.
- `mdmclient` / `ConfigurationProfiles` logs naming the payload or server.
- Apple Business Manager or federation records.
- preboot/cryptex/snapshot artifacts with hashes and timestamps.
- app clone lineage showing source, rebirth/staging path, signature drift, and TCC impact.
- packet/log evidence tying the above to a specific flow or event window.

The correct report style is:

- direct fact
- correlation
- inference
- open question
- excluded claim

## Bounty Package Answer

Yes, the combined 007 + Genesis + Hydrate plan is enough to produce a defensible bug bounty package if the evidence exists in the mounted sources and live capture windows. The strongest package will frame this as a system integrity, app trust, permission boundary, and evidence-backed security bypass chain rather than calling it a zero-click exploit.

The first acceptable deliverable is not a final accusation. It is a reproducible evidence packet that lets a reviewer verify the chain independently.
