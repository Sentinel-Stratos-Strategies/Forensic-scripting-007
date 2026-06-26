#!/usr/bin/env bash
set -euo pipefail

# atlas_submission_capture.sh
# Build a reviewer-friendly macOS app evidence bundle for bug bounty submissions.
# The script is read-only against target apps: it does not execute suspect apps,
# alter quarantine attributes, or require sudo. It recursively inventories bundles,
# captures TCC/log/process/network evidence that the current user can read, and
# zips everything with SHA-256 manifests for chain-of-custody review.

usage() {
  cat <<'USAGE'
Usage:
  ./atlas_submission_capture.sh <manifest.csv> [output_base] [triage_targets.csv]
  ./atlas_submission_capture.sh --self-test

Manifest header:
  name,suspect_app,baseline_app,process_match,pcap_glob,extra_glob,interface,pcap_seconds

Optional triage target CSV header:
  label,pattern,scope,severity,notes

Triage target searches are redacted by design for token/password/secret-like hits: the
script proves presence and location without printing credential values.

Minimum manifest columns are the first six. interface and pcap_seconds are optional.
Example:
  Atlas,/Applications/ChatGPT Atlas.app,/Applications/ChatGPT Atlas Fresh.app,"ChatGPT Atlas","/tmp/pcaps/*Atlas*.pcap","/tmp/extra/*",en0,30

Outputs:
  <output_base>/atlas_submission_capture_<UTC>/
  <output_base>/atlas_submission_capture_<UTC>.zip
USAGE
}

if [[ "${1:-}" == "--self-test" ]]; then
  bash -n "$0"
  command -v python3 >/dev/null || { echo "python3 is required for CSV parsing" >&2; exit 1; }
  command -v find >/dev/null || { echo "find is required" >&2; exit 1; }
  if ! command -v shasum >/dev/null && ! command -v sha256sum >/dev/null; then
    echo "shasum or sha256sum is required" >&2
    exit 1
  fi
  echo "self-test ok"
  exit 0
fi

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage >&2
  exit 1
fi

MANIFEST="$1"
OUT_BASE="${2:-$PWD}"
TRIAGE_TARGETS="${3:-${TRIAGE_TARGETS:-}}"
[[ -f "$MANIFEST" ]] || { echo "[FATAL] Manifest not found: $MANIFEST" >&2; exit 1; }
mkdir -p "$OUT_BASE"
OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUT_BASE/atlas_submission_capture_${RUN_TS}"
mkdir -p "$RUN_DIR"

LOG="$RUN_DIR/run.log"
SUMMARY="$RUN_DIR/summary.tsv"
ARTIFACT_SUMMARY="$RUN_DIR/artifact_summary.tsv"
FINDINGS="$RUN_DIR/findings.tsv"
TOOL_STATUS="$RUN_DIR/tool_status.tsv"
TRIAGE_HITS="$RUN_DIR/triage_hits.tsv"
TIMELINE="$RUN_DIR/timeline_events.tsv"
SQLITE_DB="$RUN_DIR/evidence.sqlite"
printf 'app\trole\tpath\tsha256\tsize\tbirth\tmtime\tbundle_id\tteam_id\tcodesign_status\tspctl_status\tnotes\n' > "$SUMMARY"
printf 'app\trole\tartifact_type\tpath\tsha256\tsize\tbirth\tmtime\tbundle_id\tteam_id\tnotes\n' > "$ARTIFACT_SUMMARY"
printf 'severity\tapp\trole\tfinding\tevidence\n' > "$FINDINGS"
printf 'tool\tstatus\tnotes\n' > "$TOOL_STATUS"
printf 'label\tseverity\tscope\tpath\tline_number\tline_sha256\tredacted_excerpt\tnotes\n' > "$TRIAGE_HITS"
printf 'timestamp\tsource\tapp\trole\tevent_type\tpath\tdetails\n' > "$TIMELINE"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
safe_name() { printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'; }
have() { command -v "$1" >/dev/null 2>&1; }
sha256_file() {
  if have shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}
write_sha256_manifest() {
  local root="$1" manifest="$2" file hash rel
  : > "$manifest"
  while IFS= read -r -d '' file; do
    [[ "$file" == "$manifest" ]] && continue
    hash="$(sha256_file "$file" 2>/dev/null || true)"
    rel="${file#"$root/"}"
    printf '%s  %s\n' "$hash" "$rel" >> "$manifest"
  done < <(find "$root" -type f -print0 | sort -z)
}
record_tool_status() {
  local tool
  for tool in "$@"; do
    if have "$tool"; then
      printf '%s\tpresent\t\n' "$tool" >> "$TOOL_STATUS"
    else
      printf '%s\tmissing\tcollection step will be skipped or recorded as unavailable\n' "$tool" >> "$TOOL_STATUS"
    fi
  done
}
sanitize_log_term() {
  printf '%s' "$1" | tr -d "'" | cut -c 1-120
}
file_size() { stat -f '%z' "$1" 2>/dev/null || stat -c '%s' "$1" 2>/dev/null || true; }
birth_time() { stat -f '%SB' -t '%Y-%m-%dT%H:%M:%SZ' "$1" 2>/dev/null || true; }
mtime_time() { stat -f '%Sm' -t '%Y-%m-%dT%H:%M:%SZ' "$1" 2>/dev/null || stat -c '%y' "$1" 2>/dev/null || true; }
plist_read() {
  local key="$1" plist="$2"
  if [[ -x /usr/libexec/PlistBuddy ]]; then
    /usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null || true
  elif have defaults; then
    defaults read "${plist%.plist}" "$key" 2>/dev/null || true
  fi
}
bundle_id_of_app() { plist_read CFBundleIdentifier "$1/Contents/Info.plist"; }
bundle_executable_of_app() { plist_read CFBundleExecutable "$1/Contents/Info.plist"; }
extract_team_id() { awk -F= '/^TeamIdentifier=/{print $2; exit}' "$1" 2>/dev/null | tr -d '[:space:]' || true; }
extract_identifier() { awk -F= '/^Identifier=/{print $2; exit}' "$1" 2>/dev/null | tr -d '[:space:]' || true; }
is_macho() { file "$1" 2>/dev/null | grep -Eq 'Mach-O.*(executable|shared library|dynamically linked|bundle)'; }
add_finding() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$FINDINGS"; }

capture_codesign() { local target="$1" out="$2"; if have codesign && codesign -dv --verbose=4 "$target" > "$out" 2>&1; then echo ok; else echo fail; fi; }
capture_spctl() { local target="$1" out="$2"; if have spctl && spctl -a -vv "$target" > "$out" 2>&1; then echo accepted; else echo rejected; fi; }

add_artifact_summary() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" >> "$ARTIFACT_SUMMARY"
}

capture_path_artifact() {
  local app_name="$1" role="$2" artifact_type="$3" path="$4" out_dir="$5"
  mkdir -p "$out_dir"; printf '%s\n' "$path" > "$out_dir/path.txt"
  local sha='' size='' birth='' mtime='' bundle_id='' team_id='' notes=''
  if [[ -f "$path" ]]; then
    sha="$(sha256_file "$path" 2>/dev/null || true)"; size="$(file_size "$path")"; birth="$(birth_time "$path")"; mtime="$(mtime_time "$path")"
    file "$path" > "$out_dir/file.txt" 2>&1 || true; stat "$path" > "$out_dir/stat.txt" 2>&1 || true; xattr -lr "$path" > "$out_dir/xattr.txt" 2>&1 || true
    printf '%s  %s\n' "$sha" "$path" > "$out_dir/sha256.txt"
    if is_macho "$path"; then
      otool -L "$path" > "$out_dir/otool_L.txt" 2>&1 || true; otool -l "$path" > "$out_dir/otool_l.txt" 2>&1 || true
      capture_codesign "$path" "$out_dir/codesign.txt" >/dev/null || true
      bundle_id="$(extract_identifier "$out_dir/codesign.txt")"; team_id="$(extract_team_id "$out_dir/codesign.txt")"
    fi
    if [[ "$path" == *.plist ]]; then plutil -p "$path" > "$out_dir/plutil.txt" 2>&1 || true; fi
    if [[ "$path" == *LaunchAgents* || "$path" == *LaunchDaemons* || "$(basename "$path")" == *.plist ]]; then
      grep -Eai 'RunAtLoad|KeepAlive|ProgramArguments|MachServices|EnvironmentVariables|DYLD|curl|osascript|python|bash|zsh|sh -c' "$path" > "$out_dir/persistence_indicators.txt" 2>/dev/null || true
    fi
    strings "$path" 2>/dev/null | grep -Eai 'tcc|camera|microphone|screen|keychain|clipboard|location|icloud|socket|http|websocket|token|authorization|bearer|api_key|password|secret|codex' | head -200 > "$out_dir/interesting_strings.txt" || true
  elif [[ -d "$path" ]]; then
    stat "$path" > "$out_dir/stat.txt" 2>&1 || true; xattr -lr "$path" > "$out_dir/xattr.txt" 2>&1 || true; notes='directory'
  else
    notes='missing'
  fi
  add_artifact_summary "$app_name" "$role" "$artifact_type" "$path" "$sha" "$size" "$birth" "$mtime" "$bundle_id" "$team_id" "$notes"
}

capture_static_bundle() {
  local app_name="$1" role="$2" app_path="$3" case_dir="$4"
  local role_dir="$case_dir/$role"
  mkdir -p "$role_dir"
  if [[ -z "$app_path" || ! -d "$app_path" ]]; then log "[WARN] Missing $role app for $app_name: $app_path"; add_finding high "$app_name" "$role" 'app path missing' "$app_path"; return 0; fi
  local exec_name bundle_id exec_path sha='' size='' birth='' mtime='' codesign_state spctl_state team_id='' ident=''
  exec_name="$(bundle_executable_of_app "$app_path")"; bundle_id="$(bundle_id_of_app "$app_path")"; exec_path="$app_path/Contents/MacOS/$exec_name"
  printf '%s\n' "$app_path" > "$role_dir/app_path.txt"; printf '%s\n' "$bundle_id" > "$role_dir/bundle_id.txt"; printf '%s\n' "$exec_name" > "$role_dir/executable_name.txt"
  [[ -f "$app_path/Contents/Info.plist" ]] && cp "$app_path/Contents/Info.plist" "$role_dir/Info.plist" 2>/dev/null || true
  if [[ -f "$exec_path" ]]; then
    sha="$(sha256_file "$exec_path")"; size="$(file_size "$exec_path")"; birth="$(birth_time "$exec_path")"; mtime="$(mtime_time "$exec_path")"
    capture_path_artifact "$app_name" "$role" outer_executable "$exec_path" "$role_dir/outer_executable"
  else add_finding high "$app_name" "$role" 'declared executable missing' "$exec_path"; fi
  codesign_state="$(capture_codesign "$app_path" "$role_dir/codesign_bundle.txt")"; spctl_state="$(capture_spctl "$app_path" "$role_dir/spctl_bundle.txt")"
  [[ -f "$exec_path" ]] && capture_codesign "$exec_path" "$role_dir/codesign_executable.txt" >/dev/null || true
  ident="$(extract_identifier "$role_dir/codesign_executable.txt")"; team_id="$(extract_team_id "$role_dir/codesign_executable.txt")"
  [[ "$codesign_state" != ok ]] && add_finding high "$app_name" "$role" 'codesign validation failed' "$role_dir/codesign_bundle.txt"
  [[ "$spctl_state" != accepted ]] && add_finding medium "$app_name" "$role" 'Gatekeeper assessment rejected or unavailable' "$role_dir/spctl_bundle.txt"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$app_name" "$role" "$app_path" "$sha" "$size" "$birth" "$mtime" "$bundle_id" "$team_id" "$codesign_state" "$spctl_state" "$ident" >> "$SUMMARY"
  printf '%s\n%s\n' "$bundle_id" "$ident" >> "$case_dir/bundle_ids.all"
  add_artifact_summary "$app_name" "$role" app_bundle "$app_path" '' '' '' '' "$bundle_id" "$team_id" "$ident"
}

recursive_inventory_bundle() {
  local app_name="$1" role="$2" app_path="$3" case_dir="$4" index=0
  local inv_dir="$case_dir/${role}_inventory"
  [[ -d "$app_path" ]] || return 0; mkdir -p "$inv_dir"
  find "$app_path" \( -type d \( -name '*.app' -o -name '*.framework' -o -name '*.xpc' -o -name '*.appex' \) -o -type f \( -name '*.plist' -o -name '*.dylib' -o -name '*.so' -o -name 'embedded.provisionprofile' -o -perm -111 \) \) -print | sort > "$inv_dir/inventory_paths.txt"
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue; index=$((index+1)); local base stem out kind='file'
    base="$(basename "$p")"; stem="$(printf '%05d_%s' "$index" "$(safe_name "$base")")"; out="$inv_dir/$stem"
    [[ -d "$p" && "$p" == *.app ]] && kind=nested_app; [[ -d "$p" && "$p" == *.xpc ]] && kind=xpc_service; [[ -d "$p" && "$p" == *.appex ]] && kind=extension
    [[ -d "$p" && "$p" == *.framework ]] && kind=framework; [[ -f "$p" && "$p" == *.plist ]] && kind=plist; [[ -f "$p" && "$p" == *.dylib ]] && kind=dylib
    [[ -f "$p" && "$p" == *embedded.provisionprofile ]] && kind=provisioning_profile
    capture_path_artifact "$app_name" "$role" "$kind" "$p" "$out"
  done < "$inv_dir/inventory_paths.txt"
}

capture_processes() {
  local app_name="$1" match="${2:-$1}" case_dir="$3"
  local proc_dir="$case_dir/process"
  mkdir -p "$proc_dir"
  pgrep -fal "$match" > "$proc_dir/pgrep.txt" 2>&1 || true
  ps auxww > "$proc_dir/ps_auxww.txt" 2>&1 || true
  grep -i -- "$match" "$proc_dir/ps_auxww.txt" > "$proc_dir/ps_matched.txt" 2>&1 || true
  printf '%s\n' "$app_name" > "$proc_dir/app_name.txt"
}
capture_user_tcc() {
  local case_dir="$1" db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  local tcc_dir="$case_dir/tcc"
  mkdir -p "$tcc_dir"
  if [[ ! -f "$db" || ! -r "$db" ]]; then
    printf 'TCC database unavailable or unreadable: %s\n' "$db" > "$tcc_dir/unavailable.txt"
    return 0
  fi
  if ! have sqlite3; then
    printf 'sqlite3 unavailable\n' > "$tcc_dir/unavailable.txt"
    return 0
  fi
  sqlite3 -readonly "$db" 'select service,client,client_type,auth_value,auth_reason,indirect_object_identifier,last_modified from access order by last_modified desc;' > "$tcc_dir/user_tcc_access.tsv" 2> "$tcc_dir/sqlite.stderr" || true
  sort -u "$case_dir/bundle_ids.all" 2>/dev/null | sed '/^$/d' > "$tcc_dir/targets.txt" || true
  : > "$tcc_dir/target_rows.tsv"
  while IFS= read -r target; do
    grep -F "$target" "$tcc_dir/user_tcc_access.tsv" >> "$tcc_dir/target_rows.tsv" || true
  done < "$tcc_dir/targets.txt"
}

capture_logs() {
  local app_name="$1" match="${2:-$1}" case_dir="$3" safe_match
  local log_dir="$case_dir/logs"
  safe_match="$(sanitize_log_term "$match")"
  mkdir -p "$log_dir"
  if ! [ -x /usr/bin/log ]; then
    printf 'macOS log command unavailable\n' > "$log_dir/unavailable.txt"
    return 0
  fi
  /usr/bin/log show --last 30m --style compact --predicate 'process == "tccd"' > "$log_dir/tccd_last30m.txt" 2> "$log_dir/tccd.stderr" || true
  /usr/bin/log show --last 30m --style compact --predicate "eventMessage CONTAINS[c] '$safe_match' OR process CONTAINS[c] '$safe_match' OR eventMessage CONTAINS[c] 'camera' OR eventMessage CONTAINS[c] 'microphone' OR eventMessage CONTAINS[c] 'screen'" > "$log_dir/privacy_filtered_last30m.txt" 2> "$log_dir/privacy_filtered.stderr" || true
  printf '%s\n' "$app_name" > "$log_dir/app_name.txt"
}

capture_login_and_codex_history() {
  local case_dir="$1" h
  local audit_dir="$case_dir/login_and_codex_audit"
  mkdir -p "$audit_dir"
  last > "$audit_dir/last_logins.txt" 2>&1 || true
  who -a > "$audit_dir/who_a.txt" 2>&1 || true
  for h in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.sh_history"; do
    if [[ -r "$h" ]]; then
      grep -Eai 'codex|atlas|tcc|tcpdump|pcap|rm |trash|delete|unlink|shred' "$h" > "$audit_dir/$(basename "$h").filtered.txt" 2>/dev/null || true
    fi
  done
  find "$HOME" -maxdepth 4 \( -iname '*codex*' -o -iname '*atlas*' -o -path '*/.Trash/*codex*' -o -path '*/.Trash/*atlas*' \) -print > "$audit_dir/codex_atlas_paths.txt" 2>/dev/null || true
  find "$HOME/.Trash" -maxdepth 3 \( -iname '*codex*' -o -iname '*atlas*' \) -print > "$audit_dir/trash_codex_atlas_paths.txt" 2>/dev/null || true
}

capture_pcap_glob() {
  local app_name="$1" glob="$2" case_dir="$3" p
  local pcap_dir="$case_dir/pcaps"
  [[ -z "$glob" ]] && return 0
  mkdir -p "$pcap_dir"
  compgen -G "$glob" > "$pcap_dir/matched_pcaps.txt" || true
  while IFS= read -r p; do
    [[ -n "$p" ]] && capture_path_artifact "$app_name" network pcap "$p" "$pcap_dir/$(safe_name "$(basename "$p")")"
  done < "$pcap_dir/matched_pcaps.txt"
}

record_short_pcap() {
  local iface="$1" seconds="$2" case_dir="$3" pid status=0
  local pcap_dir="$case_dir/live_pcap"
  [[ -z "$iface" || -z "$seconds" || "$seconds" == 0 ]] && return 0
  mkdir -p "$pcap_dir"
  if ! have tcpdump; then
    echo 'tcpdump unavailable' > "$pcap_dir/tcpdump.stderr"
    return 0
  fi
  if ! [[ "$seconds" =~ ^[0-9]+$ ]]; then
    echo "invalid pcap_seconds: $seconds" > "$pcap_dir/tcpdump.stderr"
    return 0
  fi
  tcpdump -i "$iface" -s 0 -w "$pcap_dir/capture_${iface}_${seconds}s.pcap" > "$pcap_dir/tcpdump.stdout" 2> "$pcap_dir/tcpdump.stderr" &
  pid=$!
  sleep "$seconds"
  kill -INT "$pid" 2>/dev/null || true
  wait "$pid" || status=$?
  printf 'tcpdump_exit_status=%s\n' "$status" > "$pcap_dir/tcpdump.status"
}
capture_extra_glob() {
  local app_name="$1" glob="$2" case_dir="$3" p
  local extra_dir="$case_dir/extra_artifacts"
  [[ -z "$glob" ]] && return 0
  mkdir -p "$extra_dir"
  compgen -G "$glob" > "$extra_dir/matched_paths.txt" || true
  while IFS= read -r p; do
    [[ -n "$p" ]] && capture_path_artifact "$app_name" extra extra "$p" "$extra_dir/$(safe_name "$(basename "$p")")"
  done < "$extra_dir/matched_paths.txt"
}

run_triage_targets() {
  local targets="$1" root="$2"
  [[ -z "$targets" ]] && return 0
  if [[ ! -f "$targets" ]]; then
    add_finding medium run triage "triage target CSV missing" "$targets"
    return 0
  fi
  cp "$targets" "$RUN_DIR/triage_targets.csv" 2>/dev/null || true
  python3 - "$targets" "$root" "$TRIAGE_HITS" <<'PYTRIAGE'
import csv, hashlib, re, sys
from pathlib import Path

targets_path, root, out_path = sys.argv[1:4]
text_suffixes = {'.txt', '.tsv', '.csv', '.md', '.json', '.plist', '.stdout', '.stderr', '.log'}
secret_words = re.compile(r'(token|pat|secret|password|passwd|bearer|authorization|api[_-]?key|credential)', re.I)
tokenish = re.compile(r'(?i)(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|bearer\s+[A-Za-z0-9._~+/-]{16,}|[A-Za-z0-9_./+=-]{24,})')

def is_text_candidate(path: Path) -> bool:
    if path.name in {'evidence.sqlite', 'triage_targets.csv'}:
        return False
    return path.suffix.lower() in text_suffixes or path.name in {'SHA256SUMS.txt', 'manifest.csv'}

def redact(label, pattern, line):
    redacted = tokenish.sub('[REDACTED_SECRET]', line)
    if secret_words.search(label or '') or secret_words.search(pattern or ''):
        return redacted
    return redacted[:500]

with open(targets_path, newline='') as f, open(out_path, 'a', newline='') as out:
    reader = csv.DictReader(f)
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    compiled = []
    for row in reader:
        pattern = (row.get('pattern') or '').strip()
        if not pattern:
            continue
        label = (row.get('label') or pattern or 'target').strip()
        try:
            rx = re.compile(pattern, re.I)
        except re.error:
            rx = re.compile(re.escape(pattern), re.I)
        compiled.append((label, pattern, (row.get('scope') or 'run').strip(), (row.get('severity') or 'info').strip(), (row.get('notes') or '').strip(), rx))
    for path in Path(root).rglob('*'):
        if not path.is_file() or not is_text_candidate(path):
            continue
        try:
            data = path.read_text(errors='replace').splitlines()
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for lineno, line in enumerate(data, 1):
            for label, pattern, scope, severity, notes, rx in compiled:
                if rx.search(line):
                    redacted = redact(label, pattern, line).replace('\t', ' ')[:500]
                    digest = hashlib.sha256(line.encode('utf-8', 'replace')).hexdigest()
                    writer.writerow([label, severity, scope, rel, lineno, digest, redacted, notes])
PYTRIAGE
}

build_timeline() {
  python3 - "$RUN_DIR" "$ARTIFACT_SUMMARY" "$TIMELINE" <<'PYTIMELINE'
import csv, os, sys
from datetime import datetime, timezone
from pathlib import Path
run_dir, artifact_summary, timeline = sys.argv[1:4]
events = []

def add(ts, source, app, role, event_type, path, details=''):
    if ts:
        events.append((ts, source, app, role, event_type, path, details))

if os.path.exists(artifact_summary):
    with open(artifact_summary, newline='') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            add(row.get('birth', ''), 'artifact_summary', row.get('app', ''), row.get('role', ''), 'birth', row.get('path', ''), row.get('artifact_type', ''))
            add(row.get('mtime', ''), 'artifact_summary', row.get('app', ''), row.get('role', ''), 'mtime', row.get('path', ''), row.get('artifact_type', ''))

for path in Path(run_dir).rglob('*'):
    if path.is_file():
        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        except OSError:
            continue
        rel = str(path.relative_to(run_dir))
        if rel in {'timeline_events.tsv', 'evidence.sqlite'}:
            continue
        lower = rel.lower()
        if '/pcap' in lower or lower.endswith(('.pcap', '.cap')):
            kind = 'network_artifact_mtime'
        elif '/tcc/' in lower or '/logs/' in lower:
            kind = 'privacy_log_or_tcc_mtime'
        elif '/login_and_codex_audit/' in lower:
            kind = 'login_codex_audit_mtime'
        else:
            kind = 'generated_file_mtime'
        add(ts, 'run_file', '', '', kind, rel, '')

events.sort(key=lambda x: x[0])
with open(timeline, 'w', newline='') as out:
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(['timestamp','source','app','role','event_type','path','details'])
    writer.writerows(events)
PYTIMELINE
}

build_sqlite_db() {
  python3 - "$SQLITE_DB" "$SUMMARY" "$ARTIFACT_SUMMARY" "$FINDINGS" "$TRIAGE_HITS" "$TIMELINE" "$TOOL_STATUS" <<'PYSQLITE'
import csv, os, sqlite3, sys

db, *paths = sys.argv[1:]
if os.path.exists(db):
    os.unlink(db)
conn = sqlite3.connect(db)
for table, path in zip(['summary','artifacts','findings','triage_hits','timeline','tool_status'], paths):
    if not os.path.exists(path):
        continue
    with open(path, newline='') as f:
        reader = csv.reader(f, delimiter='\t')
        try:
            header = next(reader)
        except StopIteration:
            continue
        cols = [h if h else f'col_{i}' for i, h in enumerate(header)]
        quoted = ', '.join([f'"{c}" TEXT' for c in cols])
        conn.execute(f'DROP TABLE IF EXISTS "{table}"')
        conn.execute(f'CREATE TABLE "{table}" ({quoted})')
        placeholders = ', '.join(['?'] * len(cols))
        rows = (row[:len(cols)] + [''] * max(0, len(cols) - len(row)) for row in reader)
        conn.executemany(f'INSERT INTO "{table}" VALUES ({placeholders})', rows)
conn.execute('CREATE INDEX IF NOT EXISTS idx_artifacts_path ON artifacts(path)')
conn.execute('CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline(timestamp)')
conn.execute('CREATE INDEX IF NOT EXISTS idx_triage_label ON triage_hits(label)')
conn.commit()
conn.close()
PYSQLITE
}

parse_manifest() {
  python3 - "$MANIFEST" <<'PY'
import csv, sys
with open(sys.argv[1], newline='') as f:
    for row in csv.DictReader(f):
        keys=['name','suspect_app','baseline_app','process_match','pcap_glob','extra_glob','interface','pcap_seconds']
        print('\t'.join((row.get(k) or '') for k in keys))
PY
}

write_case_docs() { local app_name="$1" case_dir="$2"; cat > "$case_dir/EXEC_SUMMARY.md" <<EOF2
# $app_name Evidence Summary

Review order: static trust checks, recursive inventory, nested apps/helpers, processes, TCC rows, privacy logs, PCAPs, login/Codex audit, then findings.tsv.

Key proof files are linked by relative path in summary.tsv, artifact_summary.tsv, and findings.tsv at the run root.
EOF2
}

log "Run directory: $RUN_DIR"; cp "$MANIFEST" "$RUN_DIR/manifest.csv"
record_tool_status python3 find file stat xattr strings codesign spctl plutil otool log sqlite3 zip tcpdump
while IFS=$'\t' read -r name suspect_app baseline_app process_match pcap_glob extra_glob iface pcap_seconds; do
  [[ -z "$name" ]] && continue; case_dir="$RUN_DIR/$(safe_name "$name")"; mkdir -p "$case_dir"; : > "$case_dir/bundle_ids.all"
  log "=== Capturing case: $name ==="
  capture_static_bundle "$name" suspect "$suspect_app" "$case_dir"; recursive_inventory_bundle "$name" suspect "$suspect_app" "$case_dir"
  capture_static_bundle "$name" baseline "$baseline_app" "$case_dir"; recursive_inventory_bundle "$name" baseline "$baseline_app" "$case_dir"
  capture_processes "$name" "$process_match" "$case_dir"; capture_user_tcc "$case_dir"; capture_logs "$name" "$process_match" "$case_dir"; capture_login_and_codex_history "$case_dir"
  capture_pcap_glob "$name" "$pcap_glob" "$case_dir"; record_short_pcap "$iface" "${pcap_seconds:-0}" "$case_dir"; capture_extra_glob "$name" "$extra_glob" "$case_dir"; write_case_docs "$name" "$case_dir"
done < <(parse_manifest)

run_triage_targets "$TRIAGE_TARGETS" "$RUN_DIR"
build_timeline
build_sqlite_db

write_sha256_manifest "$RUN_DIR" "$RUN_DIR/SHA256SUMS.txt"
cat > "$RUN_DIR/reviewer_run_order.txt" <<'EOF2'
1. Read findings.tsv for high/medium issues.
2. Compare suspect and baseline rows in summary.tsv.
3. Review codesign_bundle.txt, spctl_bundle.txt, and outer_executable artifacts.
4. Use artifact_summary.tsv and *_inventory/inventory_paths.txt for recursive bundle proof.
5. Review process, tcc, logs, pcaps, and login_and_codex_audit directories.
6. Review triage_hits.tsv for redacted target/secret/keyword hits from the optional target matrix.
7. Review timeline_events.tsv and evidence.sqlite to correlate filesystem, TCC/log, PCAP, and generated evidence timestamps.
8. Verify SHA256SUMS.txt before submitting the zip.
EOF2
( cd "$OUT_BASE" && zip -qry "$(basename "$RUN_DIR").zip" "$(basename "$RUN_DIR")" ) || true
[[ -f "$RUN_DIR.zip" ]] && sha256_file "$RUN_DIR.zip" > "$RUN_DIR.zip.sha256" || true
log "Done. Results at: $RUN_DIR"
echo "$RUN_DIR"
