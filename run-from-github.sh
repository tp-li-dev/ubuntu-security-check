#!/usr/bin/env bash
# Download a pinned revision to a private local directory, verify, then run.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
REPO=https://raw.githubusercontent.com/tp-li-dev/ubuntu-security-check
REF=''
while (( $# )); do
  case "$1" in
    --ref) [[ $# -ge 2 ]] || { echo 'Missing --ref value' >&2; exit 2; }; REF=$2; shift 2 ;;
    --) shift; break ;;
    -h|--help)
      echo 'Usage: bash run-from-github.sh --ref FULL_40_CHARACTER_COMMIT -- [diagnostic options]'
      echo 'Downloads into a private directory in the current working directory. No auto-install or upload.'
      exit 0 ;;
    *) echo "Unknown helper option: $1 (use -- before diagnostic options)" >&2; exit 2 ;;
  esac
done
[[ $REF =~ ^[a-fA-F0-9]{40}$ ]] || { echo '--ref requires a full 40-character Git commit SHA' >&2; exit 2; }
for cmd in curl sha256sum mktemp awk; do
  command -v "$cmd" >/dev/null || { echo "Missing dependency: $cmd (not installed automatically)" >&2; exit 2; }
done
FETCH_DIR=$(mktemp -d ./ubuntu-security-check-source.XXXXXXXX)
echo "Downloading pinned source into: $FETCH_DIR"
for file in ubuntu-security-check.sh SHA256SUMS; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --retry 2 \
    "$REPO/$REF/$file" --output "$FETCH_DIR/$file"
done
EXPECTED=$(awk '$2 == "ubuntu-security-check.sh" && length($1) == 64 && $1 !~ /[^0-9a-f]/ {print $1}' "$FETCH_DIR/SHA256SUMS")
[[ $EXPECTED =~ ^[a-f0-9]{64}$ ]] || { echo 'Missing/ambiguous checksum; refusing execution' >&2; exit 2; }
ACTUAL=$(sha256sum "$FETCH_DIR/ubuntu-security-check.sh")
[[ ${ACTUAL%% *} == "$EXPECTED" ]] || { echo 'Checksum mismatch; refusing execution' >&2; exit 2; }
echo "Verified diagnostic source at commit: $REF"
echo 'Source is retained locally for inspection. Running the diagnostic with your options.'
exec bash "$FETCH_DIR/ubuntu-security-check.sh" "$@"
