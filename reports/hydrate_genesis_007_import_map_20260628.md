# Hydrate / Genesis / 007 Import Map

Generated: 2026-06-28

## Source

Old Codex worktree:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools`

Existing inventory:

`/Users/fresh/Documents/Codex/2026-06-28/import-is-a-feature-that-allows/outputs/codex_worktree_inventory.md`

Related old session index:

`/Volumes/Storage/Ellis_Archive/.codex/session_index.jsonl`

## Why This Matters To 007

The Hydrate worktree contains earlier DFIR tooling that lines up with the current 007 direction. It should not be copied wholesale because it contains a stale `.venv`, binary evidence, zip bundles, old absolute paths, and a non-self-contained `.git` worktree pointer. The useful path is selective porting.

## Highest-Value Imports

### 0. Hydrate Inspector iOS shell app

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/HydrateInspectorRepo`

Imported to:

`/Users/fresh/Hydrate/HydrateInspector`

Why it helps:

- Gives the project a dedicated iPhone/iPad evidence intake lane.
- Captures device snapshot metadata and user-granted file/folder inventories.
- Exports JSON/CSV that 007 can normalize into the backend database.
- Feeds Genesis OS as a product-visible "Hydrate" lane.

### 1. Host-side iPhone snapshot

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/scripts/iphone_host_snapshot.py`

Why it helps:

- Captures USB inventory, network profile, `ioreg`, MobileDevice paths, `/var/db/lockdown`, pairing/trust logs, and recent iOS host-side files.
- This directly complements the current 007 MobileSync/iPhone backup lane.

Suggested 007 destination:

`scripts/iphone_host_snapshot.py`

Needed hardening:

- Replace hardcoded `/Users/home` references with `Path.home()`.
- Add explicit `--backup-root` support for `~/Library/Application Support/MobileSync/Backup`.
- Add hash manifest and reviewer README output.

### 2. App watcher

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/scripts/app_watch.py`

Why it helps:

- Rolling SQLite-backed watcher for process/socket/file/log samples.
- Existing target model for Chrome and developer/AI apps maps well to Atlas, Chrome, Codex, and Codex Computer Use.

Suggested 007 destination:

`scripts/app_watch.py`

Needed hardening:

- Replace Warp/Granola/Antigravity defaults with configurable app profiles.
- Add Atlas, Codex, Chrome, CUAService, and optional mounted-volume app paths.
- Include TCC sample rows and launch attribution rows.

### 3. Bundle / Mach-O inventory

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/scripts/bundle_binary_inventory.py`

Why it helps:

- Recursively inventories nested app bundles, frameworks, XPCs, app extensions, system extensions, dylibs, Mach-O files, signatures, entitlements, Gatekeeper assessment, Info.plist, and provisioning profiles.
- This is a strong fit for proving Atlas/Chrome/Codex split-trust or clone-like app-bundle drift.

Suggested 007 destination:

`scripts/bundle_binary_inventory.py`

Needed hardening:

- Integrate with `recursive_macos_volume_verify.sh` output.
- Emit TSV/CSV plus JSON/Markdown.
- Preserve `codesign`, `spctl`, entitlements, and nested-object hash outputs per case.

### 4. Cache forensic scanner

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/scripts/cache_forensic_scan.py`

Why it helps:

- Classifies Apple CloudKit caches, third-party app caches, developer caches, and suspicious indicator hits.
- Useful for Chrome/Atlas/Codex cache surfaces and the recent Full Disk Access/TCC incident.

Suggested 007 destination:

`scripts/cache_forensic_scan.py`

Needed hardening:

- Make indicator sets case-configurable.
- Add default indicators for OpenAI, Atlas, Codex, Chrome, TCC, MobileSync, configuration profiles, and app clones.
- Redact token-looking content in Markdown.

### 5. Local iCloud inventory

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/icloud_local_inventory.py`

Why it helps:

- Captures local iCloud/FileProvider archive metadata, xattrs, file kind, hashes, birth/modified/change/access times.
- Good model for 007 artifact inventory against MobileSync, CloudStorage, and recovered evidence folders.

Suggested 007 destination:

`scripts/icloud_local_inventory.py`

Needed hardening:

- Use generic path names instead of iCloud-specific naming only.
- Add output hashes and `CASE_MANIFEST.txt`.

### 6. USB recent verifier

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/usb_recent_verifier.py`

Why it helps:

- Lightweight read-only APFS metadata verifier for recent artifact windows.
- Captures birth/modified/change/access times, xattrs, file kind, hashes, and DMG verification.

Suggested 007 destination:

Merge concepts into `recursive_macos_volume_verify.sh`, or port as:

`scripts/recent_artifact_window.py`

Needed hardening:

- Generalize from USB to any source root.
- Support multiple cutoff windows and claim lanes.
- Avoid hardcoded `/Volumes/OS_BOOT/recover_snap.dmg`.

### 7. Constrained forensic MCP server

Source:

`/Volumes/Storage/Ellis_Archive/.codex/worktrees/a8d6/Hydrate_Tools/scripts/forensic_console_mcp.py`

Why it helps:

- This is the clean pattern for a safe review console: allowlisted roots, bounded text reads, redaction, read-only commands, and JSONL audit logs.
- This pairs naturally with Genesis' WebUI/plugin layer.

Suggested 007 destination:

Later phase:

`tools/forensic_console_mcp.py`

Needed hardening:

- Do not ship until dependencies are pinned and optional.
- Default roots should be `/Users/fresh/Forensic_007`, `/Volumes/Ellis`, `/Volumes/Storage`, and explicit user-supplied evidence roots.
- Keep arbitrary shell, AppleScript, write access, and app control out of scope.

## Narrative / Claim Discipline To Preserve

Hydrate docs repeatedly enforce the right evidentiary boundary:

- Separate direct filesystem facts, correlations, inferences, and open questions.
- Do not mark MDM, malware, or hostile control as proved unless a profile, agent, persistence item, packet record, rule hit, or other direct artifact supports it.
- Preserve raw timestamps and normalize time zones explicitly.
- Keep screenshots/observations separate from event execution time.

This should become a 007 report convention.

## Specific Current-Thread Relevance

- `iphone_host_snapshot.py` supports the iPhone/MobileSync lane.
- `app_watch.py` supports live Atlas/Chrome/Codex/CUAService behavior capture.
- `bundle_binary_inventory.py` supports app clone, signature, entitlement, and nested helper comparison.
- `cache_forensic_scan.py` supports Chrome/Atlas/Codex cache review and the Full Disk Access incident packet.
- `forensic_console_mcp.py` supports a future Genesis-style read-only analyst cockpit.
- `sequence_first_correlation_20260616.md` and `android_usb_utc_correlation_20260616.md` show the exact style needed for PCAP/timezone correlation.

## Do Not Import Blindly

- `.venv/`
- `.git` from `Hydrate_Tools`
- `sentinel-bundle.zip`, `sentinel-macos-bundle.zip`, `sentinel-scripts.zip`
- binary PCAPs or old evidence folders unless explicitly needed for a case packet
- `mt.py` without a separate secret-handling review
- hardcoded `/Users/home` paths

## Recommended Order

1. Port and harden `iphone_host_snapshot.py`.
2. Port and harden `bundle_binary_inventory.py`.
3. Add `app_watch.py` as a configurable watcher and wire it into `overnight_app_capture.sh`.
4. Port cache/local artifact inventory helpers.
5. Add canonical event/report wiring from Genesis after these collectors emit stable CSV/JSON.
6. Consider the constrained MCP console only after 007 outputs and roots are stable.
