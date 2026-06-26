#!/usr/bin/env bash
# Read-only recursive verifier for macOS folders, mounted volumes, app bundles, packages, and evidence trees.
set -Eeuo pipefail
IFS=$'\n\t'
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH LC_ALL=C LANG=C

OUT_BASE="$PWD/results"
CASE="macos_verify"
HASH_MODE="code"
LIMIT_FILES=0
SOURCES=()
usage(){ cat <<'USAGE'
Usage: recursive_macos_volume_verify.sh [options] SOURCE [...]
Options:
  --out-base DIR       Result parent directory (default: ./results)
  --case NAME          Case name for output directory
  --hash-mode MODE     code|all|none (default: code)
  --limit-files N      Stop after N regular files per source (0 = unlimited)
  -h, --help           Show help
Safety: never executes files from SOURCE; only reads metadata/content for hashes and static checks.
USAGE
}
while (($#)); do case "$1" in --out-base) OUT_BASE="${2:?}"; shift 2;; --case) CASE="${2:?}"; shift 2;; --hash-mode) HASH_MODE="${2:?}"; shift 2;; --limit-files) LIMIT_FILES="${2:?}"; shift 2;; -h|--help) usage; exit 0;; *) SOURCES+=("$1"); shift;; esac; done
((${#SOURCES[@]})) || { usage >&2; exit 2; }
[[ "$HASH_MODE" =~ ^(code|all|none)$ ]] || { echo "bad hash mode" >&2; exit 2; }
[[ "$LIMIT_FILES" =~ ^[0-9]+$ ]] || { echo "bad limit" >&2; exit 2; }
mkdir -p "$OUT_BASE"; OUT_BASE="$(cd "$OUT_BASE" && pwd -P)"; TS="$(date -u +%Y%m%dT%H%M%SZ)"; OUT="$OUT_BASE/${CASE}_$TS"; mkdir -p "$OUT"
LOG="$OUT/run.log"; ERR="$OUT/errors.tsv"; printf 'tool\tpath\texit\tnote\n' > "$ERR"
log(){ printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
safe(){ printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_'; }
sha(){ shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
iso(){ [[ "${1:-}" =~ ^[0-9]+$ && "$1" -gt 0 ]] && date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true; }
classify(){ local p="$1" d="$2"; case "$p" in *.app) echo app-bundle;; *.xpc) echo xpc-service;; *.framework) echo framework;; *.dylib|*.so) echo native-library;; *.plist) echo plist;; *.pkg|*.mpkg) echo installer-package;; *.dmg|*.sparsebundle) echo disk-image;; *.sh|*.bash|*.zsh) echo shell;; *.py) echo python;; *.js|*.mjs|*.cjs) echo javascript;; *.json) echo json;; *) [[ "$d" == *Mach-O* ]] && echo mach-o || { [[ -x "$p" && -f "$p" ]] && echo executable-other || echo other; };; esac; }
should_hash(){ case "$HASH_MODE:$1" in none:*) return 1;; all:*) return 0;; code:app-bundle|code:xpc-service|code:framework|code:other) return 1;; code:*) return 0;; esac; }
record_error(){ printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$ERR"; }
verify_static(){ local p="$1" rel="$2" cls="$3" dir="$4"; local od="$dir/static/$(printf '%s' "$rel" | shasum -a 256 | awk '{print $1}')_$(safe "$rel")"; mkdir -p "$od"; file "$p" >"$od/file.txt" 2>&1 || record_error file "$rel" $? fail; case "$cls" in mach-o|native-library|executable-other) codesign -dv --verbose=4 "$p" >"$od/codesign_details.txt" 2>&1 || true; codesign --verify --strict --verbose=4 "$p" >"$od/codesign_verify.txt" 2>&1 || true; otool -L "$p" >"$od/otool_L.txt" 2>&1 || true;; plist) plutil -lint "$p" >"$od/plutil_lint.txt" 2>&1 || true; plutil -p "$p" >"$od/plutil_print.txt" 2>&1 || true;; shell|python|javascript|json) head -c 1048576 "$p" >"$od/head_1MiB.txt" 2>/dev/null || true;; esac; }

{
 echo "case=$CASE"; echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "hash_mode=$HASH_MODE"; echo "limit_files=$LIMIT_FILES"; printf 'source=%s\n' "${SOURCES[@]}";
} > "$OUT/00_case_manifest.txt"
{ bash --version | head -1; shasum -a 256 "$0"; codesign --version 2>&1 || true; spctl --version 2>&1 || true; plutil -help 2>&1 | head -1; } > "$OUT/00_tool_versions.txt"

for src in "${SOURCES[@]}"; do
  [[ -e "$src" ]] || { record_error source "$src" 1 missing; continue; }
  root="$(cd "$(dirname "$src")" && pwd -P)/$(basename "$src")"; name="$(safe "$(basename "$src")")"; dir="$OUT/$name"; mkdir -p "$dir/static"
  log "Inventorying $root"
  printf 'relative_path\tkind\tmode\tuid\tgid\tsize\tmtime_utc\tbirth_utc\tflags\tsha256\tclass\tdescription\tlink_target\n' > "$dir/objects.tsv"
  count=0; partial=0
  while IFS= read -r -d '' p; do
    rel="${p#"$root"/}"; [[ "$p" == "$root" ]] && rel="."
    kind=other; desc=; link=; hash=; cls=other
    if [[ -L "$p" ]]; then kind=symlink; link="$(readlink "$p" 2>/dev/null || true)"; desc="$(file -b -h "$p" 2>/dev/null || true)"; elif [[ -d "$p" ]]; then kind=directory; desc=directory; elif [[ -f "$p" ]]; then kind=file; count=$((count+1)); if (( LIMIT_FILES>0 && count>LIMIT_FILES )); then partial=1; break; fi; desc="$(file -b "$p" 2>/dev/null || true)"; cls="$(classify "$p" "$desc")"; should_hash "$cls" && hash="$(sha "$p")"; verify_static "$p" "$rel" "$cls" "$dir"; fi
    statline="$(stat -f '%Sp|%u|%g|%z|%m|%B|%Sf' "$p" 2>/dev/null || true)"
    IFS='|' read -r mode uid gid size mt bt flags <<< "$statline" || true
    rel_e="${rel//$'\t'/\\t}"; rel_e="${rel_e//$'\n'/\\n}"
    desc_e="${desc//$'\t'/\\t}"; desc_e="${desc_e//$'\n'/\\n}"
    link_e="${link//$'\t'/\\t}"; link_e="${link_e//$'\n'/\\n}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rel_e" "$kind" "${mode:-}" "${uid:-}" "${gid:-}" "${size:-}" "$(iso "${mt:-0}")" "$(iso "${bt:-0}")" "${flags:-}" "$hash" "$cls" "$desc_e" "$link_e" >> "$dir/objects.tsv"
  done < <(find "$root" -xdev -print0 2>>"$dir/find_errors.log")
  find "$root" \( -name '*.app' -o -name '*.xpc' -o -name '*.framework' -o -name '*.pkg' -o -name '*.dmg' \) -print > "$dir/containers.txt" 2>/dev/null || true
  while IFS= read -r c; do codesign --verify --deep --strict --verbose=4 "$c" > "$dir/static/$(safe "container_$c")_codesign.txt" 2>&1 || true; spctl --assess --verbose=4 "$c" > "$dir/static/$(safe "container_$c")_spctl.txt" 2>&1 || true; done < "$dir/containers.txt"
  printf 'files_seen=%s\npartial=%s\n' "$count" "$partial" > "$dir/run_scope.txt"
done
find "$OUT" -type f ! -name case_output_hashes.sha256 -print0 | sort -z | xargs -0 shasum -a 256 > "$OUT/case_output_hashes.sha256"
touch "$OUT/COMPLETE"; log "Complete: $OUT"; echo "$OUT"
