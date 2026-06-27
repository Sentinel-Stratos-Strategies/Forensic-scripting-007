#!/usr/bin/env bash
# Read-only, high-volume recursive verifier for macOS evidence folders, volumes, app bundles, packages, and archives.
set -Eeuo pipefail
IFS=$'\n\t'

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

OUT_BASE="$PWD/results"
CASE="macos_verify"
HASH_MODE="code"
LIMIT_FILES=0
MAX_TEXT_MB=16
SOURCES=()

usage() {
  cat <<'USAGE'
Usage: recursive_macos_volume_verify.sh [options] SOURCE [...]

Options:
  --out-base DIR       Result parent directory (default: ./results)
  --case NAME          Case name for output directory
  --hash-mode MODE     code|all|none (default: code)
  --hash-all           Alias for --hash-mode all
  --no-hash            Alias for --hash-mode none
  --limit-files N      Stop after N regular files per source (0 = unlimited)
  --max-text-mb N      Maximum text-file size searched by ripgrep (default: 16)
  -h, --help           Show help

Safety: never executes files from SOURCE. It only reads metadata/content for hashing,
static parsing, code-signing verification, bundle checks, container checks, and keyword scans.
USAGE
}

while (($#)); do
  case "$1" in
    --out-base) OUT_BASE="${2:?missing output directory}"; shift 2 ;;
    --case) CASE="${2:?missing case name}"; shift 2 ;;
    --hash-mode) HASH_MODE="${2:?missing hash mode}"; shift 2 ;;
    --hash-all) HASH_MODE="all"; shift ;;
    --no-hash) HASH_MODE="none"; shift ;;
    --limit-files) LIMIT_FILES="${2:?missing file limit}"; shift 2 ;;
    --max-text-mb) MAX_TEXT_MB="${2:?missing max text size}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) SOURCES+=("$1"); shift ;;
  esac
done

((${#SOURCES[@]})) || { usage >&2; exit 2; }
[[ "$HASH_MODE" =~ ^(code|all|none)$ ]] || { echo "[FATAL] bad --hash-mode: $HASH_MODE" >&2; exit 2; }
[[ "$LIMIT_FILES" =~ ^[0-9]+$ ]] || { echo "[FATAL] --limit-files must be numeric" >&2; exit 2; }
[[ "$MAX_TEXT_MB" =~ ^[0-9]+$ ]] || { echo "[FATAL] --max-text-mb must be numeric" >&2; exit 2; }

mkdir -p "$OUT_BASE"
OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_BASE/${CASE}_$TS"
mkdir -p "$OUT"
touch "$OUT/INCOMPLETE"

LOG="$OUT/command_log.md"
ERR="$OUT/errors.tsv"
printf 'stage\tpath\texit_code\tmessage\n' > "$ERR"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
safe() { printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_' | cut -c1-100; }
path_id() { printf '%s' "$1" | shasum -a 256 | awk '{print substr($1,1,16)}'; }
escape_tsv() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//$'\t'/\\t}"
  v="${v//$'\r'/\\r}"
  v="${v//$'\n'/\\n}"
  printf '%s' "$v"
}
record_error() { printf '%s\t%s\t%s\t%s\n' "$(escape_tsv "$1")" "$(escape_tsv "$2")" "$(escape_tsv "$3")" "$(escape_tsv "$4")" >> "$ERR"; }
sha256() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

relative_path() {
  local p="$1" root="$2"
  if [[ "$p" == "$root" ]]; then printf '.'; else printf '%s' "${p#"$root"/}"; fi
}

top_name() {
  local rel="$1"
  case "$rel" in
    .) printf '_ROOT_' ;;
    */*) printf '%s' "${rel%%/*}" ;;
    *) printf '_ROOT_FILES' ;;
  esac
}

top_output_dir() {
  local top="$1" dir
  dir="$CURRENT_VOUT/directories/$(safe "$top")_$(path_id "$top")"
  mkdir -p "$dir/details"
  [[ -f "$dir/objects.tsv" ]] || printf 'relative_path\tkind\tmode\tuid\tgid\tsize\tmtime_epoch\tbirth_epoch\tflags\tsha256\tclass\tfile_description\tlink_target\n' > "$dir/objects.tsv"
  [[ -f "$dir/code_verification.tsv" ]] || printf 'relative_path\tclass\tsha256\tstatic_parse\tcodesign\tidentifier\tteam_identifier\tauthorities\txattr_names\tquarantine\tdetail_file\n' > "$dir/code_verification.tsv"
  printf '%s' "$dir"
}

classify_file() {
  local p="$1" desc="$2" lower
  lower="$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')"
  [[ "$desc" == *Mach-O* ]] && { printf 'mach-o'; return; }
  case "$lower" in
    *.dylib|*.so|*.bundle) printf 'native-library' ;;
    *.sh|*.bash|*.zsh|*.command) printf 'shell' ;;
    *.py|*.pyw) printf 'python' ;;
    *.js|*.mjs|*.cjs) printf 'javascript' ;;
    *.ts|*.tsx) printf 'typescript' ;;
    *.json) printf 'json' ;;
    *.plist) printf 'plist' ;;
    *.pkg|*.mpkg) printf 'package' ;;
    *.dmg|*.sparsebundle) printf 'disk-image' ;;
    *.zip|*.tar|*.tgz|*.tar.gz|*.tbz|*.tbz2|*.tar.bz2|*.tar.xz) printf 'archive' ;;
    *.pem|*.key|*.p12|*.pfx) printf 'key-material' ;;
    *) [[ -x "$p" && -f "$p" ]] && printf 'executable-other' || printf 'data' ;;
  esac
}

should_hash() {
  local cls="$1"
  case "$HASH_MODE" in
    all) return 0 ;;
    none) return 1 ;;
  esac
  case "$cls" in
    mach-o|native-library|shell|python|javascript|typescript|json|plist|package|disk-image|archive|key-material|executable-other) return 0 ;;
  esac
  return 1
}

static_parse() {
  local cls="$1" p="$2" detail="$3"
  case "$cls" in
    shell)
      if /bin/bash -n "$p" >"$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi ;;
    python)
      if python3 - "$p" >"$detail" 2>&1 <<'PY'
import ast
import sys
import tokenize
with tokenize.open(sys.argv[1]) as handle:
    ast.parse(handle.read(), filename=sys.argv[1])
PY
      then printf 'pass'; else printf 'fail'; fi ;;
    javascript)
      if command -v node >/dev/null 2>&1; then
        if node --check "$p" >"$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      else
        printf 'not_checked_node_missing'
      fi ;;
    json)
      if command -v jq >/dev/null 2>&1; then
        if jq empty "$p" >"$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi
      elif plutil -lint "$p" >"$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi ;;
    plist)
      if plutil -lint "$p" >"$detail" 2>&1; then printf 'pass'; else printf 'fail'; fi ;;
    typescript)
      printf 'not_checked_project_compiler_required' ;;
    *)
      printf 'not_applicable' ;;
  esac
}

write_object_row() {
  local out_file="$1" rel="$2" kind="$3" mode="$4" uid="$5" gid="$6" size="$7" mt="$8" bt="$9" flags="${10}" hash="${11}" cls="${12}" desc="${13}" link="${14}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(escape_tsv "$rel")" "$(escape_tsv "$kind")" "$(escape_tsv "$mode")" "$(escape_tsv "$uid")" "$(escape_tsv "$gid")" \
    "$(escape_tsv "$size")" "$(escape_tsv "$mt")" "$(escape_tsv "$bt")" "$(escape_tsv "$flags")" "$(escape_tsv "$hash")" \
    "$(escape_tsv "$cls")" "$(escape_tsv "$desc")" "$(escape_tsv "$link")" >> "$out_file"
}

verify_code_file() {
  local p="$1" rel="$2" cls="$3" hash="$4" top_dir="$5" item detail_rel detail parse_status codesign_status identifier team authorities xattrs quarantine
  item="$(path_id "$rel")_$(safe "$(basename "$rel")")"
  detail_rel="details/${item}.txt"
  detail="$top_dir/$detail_rel"
  : > "$detail"

  parse_status="$(static_parse "$cls" "$p" "$detail")"
  codesign_status="not_applicable"
  identifier=""
  team=""
  authorities=""

  case "$cls" in
    mach-o|native-library|executable-other)
      {
        echo '[file]'
        file "$p"
        echo
        echo '[codesign verify]'
        codesign --verify --strict --verbose=4 "$p"
      } >> "$detail" 2>&1 || true
      if codesign --verify --strict --verbose=4 "$p" >/dev/null 2>&1; then
        codesign_status="valid"
      elif rg -q 'not signed at all|code object is not signed' "$detail" 2>/dev/null; then
        codesign_status="unsigned"
      else
        codesign_status="invalid"
      fi
      {
        echo
        echo '[codesign metadata]'
        codesign -dvvv "$p"
        echo
        echo '[entitlements]'
        codesign -d --entitlements :- "$p"
        echo
        echo '[otool -L]'
        otool -L "$p"
        echo
        echo '[otool -l]'
        otool -l "$p"
      } >> "$detail" 2>&1 || true
      identifier="$(awk -F= '/^Identifier=/{print $2; exit}' "$detail")"
      team="$(awk -F= '/^TeamIdentifier=/{print $2; exit}' "$detail")"
      authorities="$(awk -F= '/^Authority=/{if (n++) printf ";"; printf "%s",$2}' "$detail")"
      ;;
  esac

  xattrs="$(xattr "$p" 2>/dev/null | paste -sd, - || true)"
  quarantine="$(xattr -p com.apple.quarantine "$p" 2>/dev/null | tr '\t\r\n' '   ' || true)"
  [[ -s "$detail" ]] || { rm -f "$detail"; detail_rel=""; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(escape_tsv "$rel")" "$(escape_tsv "$cls")" "$(escape_tsv "$hash")" "$(escape_tsv "$parse_status")" \
    "$(escape_tsv "$codesign_status")" "$(escape_tsv "$identifier")" "$(escape_tsv "$team")" "$(escape_tsv "$authorities")" \
    "$(escape_tsv "$xattrs")" "$(escape_tsv "$quarantine")" "$(escape_tsv "$detail_rel")" >> "$top_dir/code_verification.tsv"
}

verify_app_bundles() {
  local root="$1" volume_out="$2" report app rel item detail_rel detail sign gate identifier team authorities
  report="$volume_out/app_bundles.tsv"
  printf 'relative_path\tcodesign\tgatekeeper\tidentifier\tteam_identifier\tauthorities\tdetail_file\n' > "$report"
  while IFS= read -r -d '' app; do
    rel="$(relative_path "$app" "$root")"
    item="$(path_id "$rel")_$(safe "$(basename "$rel")")"
    detail_rel="bundle_details/${item}.txt"
    detail="$volume_out/$detail_rel"
    mkdir -p "$(dirname "$detail")"
    {
      echo '[bundle codesign verify]'
      codesign --verify --deep --strict --verbose=4 "$app"
    } > "$detail" 2>&1 || true
    if codesign --verify --deep --strict --verbose=4 "$app" >/dev/null 2>&1; then sign="valid"; else sign="invalid_or_unsigned"; fi
    {
      echo
      echo '[bundle codesign metadata]'
      codesign -dvvv "$app"
      echo
      echo '[bundle entitlements]'
      codesign -d --entitlements :- "$app"
      echo
      echo '[gatekeeper]'
      spctl --assess --type execute -vv "$app"
    } >> "$detail" 2>&1 || true
    if spctl --assess --type execute -vv "$app" >/dev/null 2>&1; then gate="accepted"; else gate="rejected_or_unavailable"; fi
    identifier="$(awk -F= '/^Identifier=/{print $2; exit}' "$detail")"
    team="$(awk -F= '/^TeamIdentifier=/{print $2; exit}' "$detail")"
    authorities="$(awk -F= '/^Authority=/{if (n++) printf ";"; printf "%s",$2}' "$detail")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(escape_tsv "$rel")" "$sign" "$gate" "$(escape_tsv "$identifier")" "$(escape_tsv "$team")" "$(escape_tsv "$authorities")" "$(escape_tsv "$detail_rel")" >> "$report"
  done < <(find "$root" -xdev -type d -name '*.app' -prune -print0 2>> "$volume_out/find_errors.log")
}

verify_containers() {
  local root="$1" volume_out="$2" report p rel lower hash item detail_rel detail class structure checksum signature gate trust
  report="$volume_out/container_verification.tsv"
  printf 'relative_path\tclass\tsha256\tstructure\tchecksum\tsignature\tgatekeeper\ttrust\tdetail_file\n' > "$report"
  while IFS= read -r -d '' p; do
    rel="$(relative_path "$p" "$root")"
    lower="$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')"
    hash="$(sha256 "$p")"
    item="$(path_id "$rel")_$(safe "$(basename "$rel")")"
    detail_rel="container_details/${item}.txt"
    detail="$volume_out/$detail_rel"
    mkdir -p "$(dirname "$detail")"
    class="archive"; structure="not_checked"; checksum="not_applicable"; signature="not_applicable"; gate="not_applicable"; trust="not_assessed"
    case "$lower" in
      *.pkg|*.mpkg)
        class="package"
        {
          echo '[pkg signature]'
          pkgutil --check-signature "$p"
          echo
          echo '[gatekeeper]'
          spctl --assess --type install -vv "$p"
          echo
          echo '[xar listing: first 5000 entries]'
          xar -tf "$p" | awk 'NR<=5000'
        } > "$detail" 2>&1 || true
        if xar -tf "$p" >/dev/null 2>&1; then structure="listable"; else structure="invalid"; fi
        if pkgutil --check-signature "$p" >/dev/null 2>&1; then signature="valid"; else signature="invalid_or_unsigned"; fi
        if spctl --assess --type install -vv "$p" >/dev/null 2>&1; then gate="accepted"; else gate="rejected"; fi
        [[ "$signature" == "valid" && "$gate" == "accepted" ]] && trust="trusted" || trust="untrusted"
        ;;
      *.dmg|*.sparsebundle)
        class="disk-image"
        {
          echo '[image info]'
          hdiutil imageinfo "$p"
          echo
          echo '[image verify]'
          hdiutil verify "$p"
          echo
          echo '[codesign verify]'
          codesign --verify --strict --verbose=4 "$p"
          echo
          echo '[gatekeeper primary signature]'
          spctl --assess --type open --context context:primary-signature -vv "$p"
        } > "$detail" 2>&1 || true
        if hdiutil imageinfo "$p" >/dev/null 2>&1; then structure="valid"; else structure="invalid"; fi
        if hdiutil verify "$p" >/dev/null 2>&1; then checksum="valid"; else checksum="invalid"; fi
        if codesign --verify --strict --verbose=4 "$p" >/dev/null 2>&1; then signature="valid"; else signature="invalid_or_unsigned"; fi
        if spctl --assess --type open --context context:primary-signature -vv "$p" >/dev/null 2>&1; then gate="accepted"; else gate="rejected"; fi
        [[ "$structure" == "valid" && "$checksum" == "valid" && "$signature" == "valid" && "$gate" == "accepted" ]] && trust="trusted" || trust="untrusted"
        ;;
      *.zip)
        unzip -Z1 "$p" 2>&1 | awk 'NR<=5000' > "$detail" || true
        if unzip -Z1 "$p" >/dev/null 2>&1; then structure="listable"; else structure="invalid"; fi
        trust="untrusted_unsigned_archive"
        ;;
      *)
        tar -tf "$p" 2>&1 | awk 'NR<=5000' > "$detail" || true
        if tar -tf "$p" >/dev/null 2>&1; then structure="listable"; else structure="invalid"; fi
        trust="untrusted_unsigned_archive"
        ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(escape_tsv "$rel")" "$class" "$hash" "$structure" "$checksum" "$signature" "$gate" "$trust" "$(escape_tsv "$detail_rel")" >> "$report"
  done < <(find "$root" -xdev -type f \( -iname '*.pkg' -o -iname '*.mpkg' -o -iname '*.dmg' -o -iname '*.sparsebundle' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tgz' -o -iname '*.tar.gz' -o -iname '*.tbz' -o -iname '*.tbz2' -o -iname '*.tar.bz2' -o -iname '*.tar.xz' \) -print0 2>> "$volume_out/find_errors.log")
}

collect_high_signal_paths() {
  local root="$1" volume_out="$2"
  find "$root" -xdev \( \
    -path '*/LaunchAgents/*' -o -path '*/LaunchDaemons/*' -o \
    -path '*/ConfigurationProfiles/*' -o -path '*/Managed Preferences/*' -o \
    -name 'mdmclient.plist' -o -name 'CloudConfigurationDetails.plist' -o \
    -name 'PayloadManifest.plist' -o -name 'TCC.db' -o -name 'TCCAccessory.db' -o \
    -name 'appsscript.json' -o -name '.clasprc.json' -o -name 'workspace_admin_audit.json' \
  \) -print 2>> "$volume_out/find_errors.log" > "$volume_out/high_signal_paths.txt" || true

  if command -v rg >/dev/null 2>&1; then
    rg --hidden --no-follow --no-messages --with-filename -i -n -o \
      --max-filesize "${MAX_TEXT_MB}M" \
      -g '!**/.git/objects/**' -g '!**/node_modules/**' -g '!**/.venv/**' -g '!**/venv/**' \
      -g '!**/Library/Caches/**' -g '!**/homebrew/Cellar/**' \
      -g '!*.jmod' -g '!*.jar' -g '!*.zip' -g '!*.tar*' -g '!*.dmg' -g '!*.pkg' \
      -e 'token|secret|api[_-]?key|password|passphrase|private[ _-]?key|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' \
      "$root" > "$volume_out/sensitive_keyword_hits_redacted.txt" 2>> "$volume_out/rg_errors.log" || true

    rg --hidden --no-follow --no-messages --with-filename -i -n -o \
      --max-filesize "${MAX_TEXT_MB}M" \
      -g '!**/.git/objects/**' -g '!**/node_modules/**' -g '!**/.venv/**' -g '!**/venv/**' \
      -g '!**/Library/Caches/**' -g '!**/homebrew/Cellar/**' \
      -g '!*.jmod' -g '!*.jar' -g '!*.zip' -g '!*.tar*' -g '!*.dmg' -g '!*.pkg' \
      -e 'mdmBaseURL|axm-servicediscovery|com\.apple\.remotemanagement|ConfigurationProfiles|RunAtLoad|KeepAlive|ProgramArguments|osascript|curl[[:space:]]|base64|cloudflare|warp|codex-local|unsloth|gemma|atlas|openai|owlbridge|tccd|pcap' \
      "$root" > "$volume_out/forensic_keyword_hits.txt" 2>> "$volume_out/rg_errors.log" || true
  else
    printf 'ripgrep unavailable; text search not run\n' > "$volume_out/rg_errors.log"
  fi
}

summarize_directories() {
  local volume_out="$1" report dir objects candidates parse_failures native_failures
  report="$volume_out/directory_summary.tsv"
  printf 'directory_group\tobjects\tcode_candidates\tparse_failures\tinvalid_or_unsigned_native_code\n' > "$report"
  for dir in "$volume_out"/directories/*; do
    [[ -d "$dir" ]] || continue
    objects="$(awk 'NR>1{n++} END{print n+0}' "$dir/objects.tsv")"
    candidates="$(awk 'NR>1{n++} END{print n+0}' "$dir/code_verification.tsv")"
    parse_failures="$(awk -F '\t' 'NR>1 && $4=="fail"{n++} END{print n+0}' "$dir/code_verification.tsv")"
    native_failures="$(awk -F '\t' 'NR>1 && ($5=="invalid" || $5=="unsigned"){n++} END{print n+0}' "$dir/code_verification.tsv")"
    printf '%s\t%s\t%s\t%s\t%s\n' "$(basename "$dir")" "$objects" "$candidates" "$parse_failures" "$native_failures" >> "$report"
  done
}

inventory_source() {
  local src="$1" root name count partial p rel top top_dir kind desc link hash cls statline mode uid gid size mt bt flags
  [[ -e "$src" ]] || { record_error source "$src" 1 missing; return 0; }
  root="$(cd "$(dirname "$src")" && pwd -P)/$(basename "$src")"
  name="$(safe "$(basename "$root")")_$(path_id "$root")"
  CURRENT_VOUT="$OUT/$name"
  export CURRENT_VOUT
  mkdir -p "$CURRENT_VOUT/directories"
  log "Starting source: $root"

  {
    echo "source=$root"
    echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    df "$root" 2>/dev/null || true
    mount | grep -F " on $(df "$root" 2>/dev/null | awk 'NR==2{print $NF}') " || true
    ls -laOe@ "$root" 2>&1 || true
  } > "$CURRENT_VOUT/00_source_context.txt"

  count=0
  partial=0
  while IFS= read -r -d '' p; do
    rel="$(relative_path "$p" "$root")"
    top="$(top_name "$rel")"
    top_dir="$(top_output_dir "$top")"
    kind="other"; desc=""; link=""; hash=""; cls="not_applicable"

    if [[ -L "$p" ]]; then
      kind="symlink"; link="$(readlink "$p" 2>/dev/null || true)"; desc="$(file -b -h "$p" 2>/dev/null || true)"
    elif [[ -d "$p" ]]; then
      kind="directory"; desc="directory"
    elif [[ -f "$p" ]]; then
      kind="file"; count=$((count+1))
      if (( LIMIT_FILES > 0 && count > LIMIT_FILES )); then partial=1; break; fi
      desc="$(file -b "$p" 2>/dev/null || true)"
      cls="$(classify_file "$p" "$desc")"
      if should_hash "$cls"; then
        hash="$(sha256 "$p")"
        [[ -n "$hash" ]] || record_error sha256 "$rel" 1 "hash failed"
      fi
    fi

    statline="$(stat -f '%Sp|%u|%g|%z|%m|%B|%Sf' "$p" 2>/dev/null || true)"
    IFS='|' read -r mode uid gid size mt bt flags <<< "$statline" || true
    write_object_row "$top_dir/objects.tsv" "$rel" "$kind" "${mode:-}" "${uid:-}" "${gid:-}" "${size:-}" "${mt:-}" "${bt:-}" "${flags:-}" "$hash" "$cls" "$desc" "$link"

    case "$cls" in
      mach-o|native-library|shell|python|javascript|typescript|json|plist|executable-other)
        verify_code_file "$p" "$rel" "$cls" "$hash" "$top_dir" ;;
    esac
  done < <(find "$root" -xdev -print0 2>> "$CURRENT_VOUT/find_errors.log")

  printf 'file_limit=%s\nfiles_seen=%s\npartial=%s\n' "$LIMIT_FILES" "$count" "$partial" > "$CURRENT_VOUT/run_scope.txt"
  verify_app_bundles "$root" "$CURRENT_VOUT"
  verify_containers "$root" "$CURRENT_VOUT"
  collect_high_signal_paths "$root" "$CURRENT_VOUT"
  summarize_directories "$CURRENT_VOUT"
  find "$CURRENT_VOUT" -type f ! -name output_hashes.sha256 -print0 | sort -z | xargs -0 shasum -a 256 > "$CURRENT_VOUT/output_hashes.sha256"
  log "Finished source: $root (files seen: $count, partial: $partial)"
}

{
  echo "case=$CASE"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "script=$0"
  echo "script_sha256=$(shasum -a 256 "$0" | awk '{print $1}')"
  echo "hash_mode=$HASH_MODE"
  echo "limit_files=$LIMIT_FILES"
  echo "max_text_mb=$MAX_TEXT_MB"
  printf 'source=%s\n' "${SOURCES[@]}"
} > "$OUT/00_case_manifest.txt"

{
  bash --version | head -n 1
  shasum -a 256 "$0"
  file --version 2>&1 | head -n 1 || true
  codesign --version 2>&1 || true
  spctl --version 2>&1 || true
  plutil -help 2>&1 | head -n 1 || true
  rg --version 2>&1 | head -n 1 || true
  jq --version 2>&1 || true
  python3 --version 2>&1 || true
  node --version 2>&1 || true
} > "$OUT/00_tool_versions.txt"

log "Case output: $OUT"
for src in "${SOURCES[@]}"; do
  inventory_source "$src"
done

rm -f "$OUT/INCOMPLETE"
touch "$OUT/COMPLETE"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/00_utc_end.txt"
find "$OUT" -type f ! -name case_output_hashes.sha256 -print0 | sort -z | xargs -0 shasum -a 256 > "$OUT/case_output_hashes.sha256"
log "Collection complete: $OUT"
echo "$OUT"
