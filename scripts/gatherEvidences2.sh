#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

EVIDENCE_DIR="${EVIDENCE_DIR:-/root/evidences}"
IP_LIST="${IP_LIST:-/var/lib/go-log-scythe/banned_ips.txt}"

DEFAULT_LOGS=(
  /var/log/nginx/access.log
  /var/log/nginx/access.log.1
  /var/log/nginx/access.log.*.gz
)

die() { echo "ERROR: $*" >&2; exit 1; }

expand_existing_files() {
  local -a out=()
  local p f
  shopt -s nullglob
  for p in "$@"; do
    for f in $p; do
      [[ -f "$f" ]] && out+=("$f")
    done
  done
  shopt -u nullglob
  printf '%s\n' "${out[@]}"
}

# Stream logs (plain + gz) to stdout
stream_logs() {
  local f
  for f in "$@"; do
    if [[ "$f" == *.gz ]]; then
      zcat -- "$f"
    else
      cat -- "$f"
    fi
  done
}

cd "$EVIDENCE_DIR" 2>/dev/null || die "Cannot cd to $EVIDENCE_DIR"
[[ -r "$IP_LIST" ]] || die "IP list not readable: $IP_LIST"

echo "## listing already gathered ip info"
done_list="$(mktemp)"
missing_list="$(mktemp)"
trap 'rm -f "$done_list" "$missing_list"' EXIT

shopt -s nullglob
done_files=( *_evidence.txt )
shopt -u nullglob

if ((${#done_files[@]})); then
  printf '%s\n' "${done_files[@]}" \
    | sed 's/_evidence\.txt$//' \
    | LC_ALL=C sort -u >"$done_list"
else
  : >"$done_list"
fi

# choose logs from args or defaults
if (($#)); then
  mapfile -t LOG_FILES < <(expand_existing_files "$@")
else
  mapfile -t LOG_FILES < <(expand_existing_files "${DEFAULT_LOGS[@]}")
fi
((${#LOG_FILES[@]})) || die "No log files found."

echo "## using log files:"
printf '   - %s\n' "${LOG_FILES[@]}"

# compute missing IPs (unique, sorted)
LC_ALL=C sort -u "$IP_LIST" >"$missing_list.all"
LC_ALL=C sort -u "$done_list" >"$missing_list.done"
LC_ALL=C comm -23 "$missing_list.all" "$missing_list.done" >"$missing_list"
rm -f "$missing_list.all" "$missing_list.done"

# Extra safety: if evidence file already exists (race/manual), skip it anyway later.
# Also avoid writing empty files by writing to temp-per-ip and only moving if non-empty.

echo "## scanning logs once and writing evidences (no overwrite, no empty files)"

# awk strategy:
# - load missing IPs into a set
# - for each log line, if it contains one of these IPs, append to a temp file for that IP
#   (we match on word boundaries-ish to reduce accidental substring hits)
# - at END, for each IP with matches:
#     if final evidence file doesn't exist and temp file is non-empty -> move it

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir" "$done_list" "$missing_list"' EXIT

# Use gawk if available for better performance; plain awk also works.
AWK_BIN="${AWK_BIN:-awk}"

stream_logs "${LOG_FILES[@]}" | "$AWK_BIN" -v ipfile="$missing_list" -v outdir="$tmpdir" '
  BEGIN {
    while ((getline ip < ipfile) > 0) {
      if (ip != "") wanted[ip]=1
    }
    close(ipfile)
  }
  {
    # Very common Nginx access log format starts with "$remote_addr"
    # If yours does, this is fast and accurate:
    ip=$1

    # If not, fallback: try to find any wanted IP as a whole token would be expensive.
    # But we assume remote_addr is field 1.
    if (wanted[ip]) {
      print $0 >> (outdir "/" ip ".tmp")
      seen[ip]=1
    }
  }
  END {
    # nothing else here
  }
'

# Finalize: move non-empty temp files to evidence files, but never overwrite
shopt -s nullglob
for tf in "$tmpdir"/*.tmp; do
  ip="$(basename "$tf" .tmp)"
  final="${ip}_evidence.txt"

  if [[ -e "$final" ]]; then
    echo "## skipping $ip: evidence already exists ($final)"
    continue
  fi

  if [[ -s "$tf" ]]; then
    mv -n -- "$tf" "$final"  # -n = no clobber
    echo "#### wrote evidences for $ip -> $final"
  else
    # Should not happen, but keep the rule: do not create empty files
    rm -f -- "$tf"
  fi
done
shopt -u nullglob

echo "## done"