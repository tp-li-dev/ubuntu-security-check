#!/usr/bin/env bash
# Collect local evidence. Never install packages, upload reports, or alter services.
set -uo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
VERSION=0.1.0
DAYS=7
LIMIT=30
USE_SUDO=0
WANT_ZIP=0
FORMAT=both
DEST=""
usage() {
  cat <<'HELP'
Ubuntu Security Check (local, read-only diagnostic collection)
Usage: bash ubuntu-security-check.sh [options]
  --sudo              Ask sudo for read access to protected evidence
  --days N            Authentication-log window, 1..365 (default: 7)
  --timeout N         Per-check timeout, 5..300 seconds (default: 30)
  --format md|both    Markdown only, or Markdown + HTML (default: both)
  --output DIRECTORY New report directory; existing paths are refused
  --zip               Also create a ZIP next to the report directory
  --version           Print version
  -h, --help          Show this help
No package installation, network requests, configuration changes, or uploads.
Reports contain sensitive host/account/IP information. Review before sharing.
HELP
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
need_value() { [[ $# -ge 2 && -n $2 ]] || die "Missing value for $1"; }
while (( $# )); do
  case "$1" in
    --sudo) USE_SUDO=1; shift ;;
    --zip) WANT_ZIP=1; shift ;;
    --days) need_value "$@"; DAYS=$2; shift 2 ;;
    --timeout) need_value "$@"; LIMIT=$2; shift 2 ;;
    --format) need_value "$@"; FORMAT=$2; shift 2 ;;
    --output) need_value "$@"; DEST=$2; shift 2 ;;
    --version) printf '%s\n' "$VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done
[[ $DAYS =~ ^[1-9][0-9]{0,2}$ ]] && (( DAYS <= 365 )) || die '--days must be 1..365'
[[ $LIMIT =~ ^[1-9][0-9]{0,2}$ ]] && (( LIMIT >= 5 && LIMIT <= 300 )) || die '--timeout must be 5..300'
[[ $FORMAT == md || $FORMAT == both ]] || die '--format must be md or both'
[[ -r /etc/os-release ]] || die 'Linux /etc/os-release is required'
# Read just the ID field; do not source configuration as executable shell code.
OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
[[ $OS_ID == ubuntu ]] || die "Ubuntu required (detected: $OS_ID)"
for cmd in timeout date mkdir chmod awk sed sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required command missing: $cmd (no packages installed)"
done
if [[ $FORMAT == both || $WANT_ZIP == 1 ]]; then
  command -v python3 >/dev/null 2>&1 || die 'HTML/ZIP requires python3. Use --format md without --zip, or install python3 yourself.'
fi
PRIV=()
CAN_PRIV=0
if (( EUID == 0 )); then CAN_PRIV=1
elif (( USE_SUDO )); then
  command -v sudo >/dev/null 2>&1 || die 'sudo is unavailable'
  sudo -v || die 'sudo authentication failed; no report collected'
  PRIV=(sudo -n)
  CAN_PRIV=1
fi
[[ -n $DEST ]] || DEST="./reports/$(date -u +%Y-%m-%d_%H%M%SZ)-$$"
# mkdir refuses existing directories and symlinks; never overwrite a report.
PARENT=$(dirname -- "$DEST")
mkdir -p -- "$PARENT" || die 'Cannot create output parent'
mkdir -m 700 -- "$DEST" || die 'Output directory already exists or cannot be created'
DEST=$(cd -- "$DEST" && pwd -P) || die 'Cannot resolve output directory'
mkdir -m 700 -- "$DEST/evidence" || die 'Cannot create evidence directory'
INDEX="$DEST/checks.tsv"
printf 'id\tstatus\texit_code\ttitle\n' > "$INDEX"
START=$(date -u +%FT%TZ)
skip() {
  printf '%s\n' "$3" > "$DEST/evidence/$1.txt"
  printf '%s\tSKIPPED\t-\t%s\n' "$1" "$2" >> "$INDEX"
  printf '[SKIPPED] %s\n' "$2"
}
collect() {
  local id=$1 title=$2 rc status
  shift 2
  if ! command -v "$1" >/dev/null 2>&1; then skip "$id" "$title" "Command unavailable: $1"; return; fi
  timeout --signal=TERM --kill-after=3s "${LIMIT}s" "$@" > "$DEST/evidence/$id.txt" 2>&1
  rc=$?
  case $rc in 0) status=COLLECTED ;; 124|137) status=TIMEOUT ;; *) status=ERROR ;; esac
  printf '%s\t%s\t%s\t%s\n' "$id" "$status" "$rc" "$title" >> "$INDEX"
  printf '[%s] %s\n' "$status" "$title"
}
protected() {
  local id=$1 title=$2
  shift 2
  if (( ! CAN_PRIV )); then skip "$id" "$title" 'Protected evidence not collected. Rerun with --sudo if authorized.'; return; fi
  if ! command -v "$1" >/dev/null 2>&1; then skip "$id" "$title" "Command unavailable: $1"; return; fi
  collect "$id" "$title" "${PRIV[@]}" "$@"
}
collect 01-system 'OS, kernel and time' bash -c 'date -Is; cat /etc/os-release; uname -a; uptime'
collect 02-sessions 'Current login sessions' who -u
collect 03-logins 'Recent successful login records (wtmp, latest 50)' last -ai -n 50
protected 04-failed-logins 'Recent failed login records (btmp, latest 50)' lastb -ai -n 50
protected 05-ssh-accepted "SSH accepted authentication (last $DAYS days, latest 300 records)" journalctl --no-pager -o short-iso --since "$DAYS days ago" -t sshd -t sshd-session --grep 'Accepted ' -n 300
protected 06-ssh-rejected "SSH rejected authentication (last $DAYS days, latest 300 records)" journalctl --no-pager -o short-iso --since "$DAYS days ago" -t sshd -t sshd-session --grep 'Failed |Invalid user|authentication failure' -n 300
protected 07-ssh-config 'SSH effective global configuration (selected fields)' bash -o pipefail -c '/usr/sbin/sshd -T | awk '\''/^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|authenticationmethods|permitemptypasswords|maxauthtries|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile) /'\'''
protected 08-listeners 'Listening TCP/UDP sockets and owning processes' ss -lntup
protected 09-connections 'Established TCP connections and owning processes' ss -ntp state established
protected 10-ufw 'UFW firewall state' ufw status verbose
protected 11-nftables 'nftables rules (may coexist with UFW/container rules)' nft list ruleset
protected 12-iptables 'IPv4 iptables rules' iptables-save
protected 13-ip6tables 'IPv6 iptables rules' ip6tables-save
collect 14-accounts 'Local accounts (no password hashes)' awk -F: '{print $1 ":uid=" $3 ":gid=" $4 ":home=" $6 ":shell=" $7}' /etc/passwd
collect 15-admin-groups 'Administrative groups' getent group sudo adm
collect 16-processes 'Process metadata (arguments/environment excluded)' ps -eo user,pid,ppid,lstart,etimes,pcpu,pmem,comm --sort=-pcpu
collect 17-services 'Running services' systemctl --no-pager --plain --type=service --state=running
collect 18-enabled-units 'Enabled unit files' systemctl --no-pager --plain list-unit-files --state=enabled
collect 19-timers 'Scheduled system timers' systemctl --no-pager --plain list-timers --all
collect 20-failed-units 'Failed units' systemctl --no-pager --plain --failed
protected 21-persistence-metadata 'Cron and local service file metadata (contents excluded)' bash -c 'for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs /etc/systemd/system /etc/rc.local /etc/ld.so.preload; do if [ -e "$p" ]; then find "$p" -maxdepth 2 -printf "%M %u:%g %TY-%Tm-%TdT%TH:%TM:%TS %p -> %l\n"; fi; done'
protected 22-ssh-key-fingerprints 'Standard authorized_keys fingerprints (no key contents/comments)' bash -c 'bad=0; while IFS=: read -r name _ uid gid gecos home shell; do [ "$uid" = 0 ] || [ "$uid" -ge 1000 ] || continue; [ "$home" != /nonexistent ] || continue; for key in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do if [ -f "$key" ]; then printf "Account: %s; file: %s\n" "$name" "$key"; stat -c "mode=%a owner=%U:%G modified=%y" "$key"; if ! ssh-keygen -lf "$key" -E sha256 | awk '\''{print $1, $2, $NF}'\''; then bad=1; fi; fi; done; done < /etc/passwd; exit "$bad"'
collect 23-upgrades 'Available updates from existing APT indexes (no index refresh)' apt list --upgradable
collect 24-apt-index-age 'APT index timestamps (staleness must be reviewed)' bash -c 'find /var/lib/apt/lists -maxdepth 1 -type f -name "*InRelease" -printf "%TY-%Tm-%TdT%TH:%TM:%TS %f\n"; if [ -e /var/run/reboot-required ]; then cat /var/run/reboot-required; fi'
collect 25-security-services 'Security service state (absence alone is not a finding)' bash -c 'for unit in ufw fail2ban auditd unattended-upgrades apparmor; do printf "\n%s: " "$unit"; systemctl is-active "$unit" || :; done'
collect 26-disk 'Filesystem usage' df -h -x tmpfs -x devtmpfs
collect 27-user-units 'Invoking account user service/timer state (may be unavailable)' systemctl --user --no-pager --plain list-units --all --type=service --type=timer

# Escape all evidence as indented Markdown code, never as trusted report markup.
REPORT="$DEST/report.md"
{
  printf '# Ubuntu Security Check\n\n'
  printf -- '- Version: %s\n- Started (UTC): %s\n- Finished (UTC): %s\n- Log window: %s days\n- Protected reads requested: %s\n\n' "$VERSION" "$START" "$(date -u +%FT%TZ)" "$DAYS" "$CAN_PRIV"
  cat <<'NOTES'
## Interpretation / 読み方

This report collects evidence. It does not certify that the server is safe or uncompromised.
COLLECTED means the command completed, not that its result passed a security check.
ERROR, TIMEOUT and SKIPPED mean the corresponding check is incomplete.

侵入の有無や安全性を自動断定するレポートではありません。ログの保持期間・欠落・改ざん、
サーバー外のクラウドFW、コンテナ内部、別のSSH設定ファイル、Match条件ごとのSSH設定、
独自の鍵取得コマンド、標準パス外の鍵、全ユーザーのユーザーサービスは網羅しません。
SSH認証ログは各300件、wtmp/btmpは各50件が上限です。欠落やログローテーションにより履歴が見えない場合があります。
APT情報は保存済みインデックスの内容であり、現在の修正提供状況を保証しません。
権限のない実行では、管理者向けの項目がSKIPPEDになります。

## Review checklist / 要確認事項

- 成功したログイン元・アカウント・時刻を、自分の操作履歴と照合する。
- 外部向け待ち受けポートを意図したサービスと照合する。ローカルFWだけで外部到達性は断定しない。
- SSHのrootログイン・パスワード認証が運用方針に合うか確認する。
- アカウント・鍵の指紋・サービス・タイマー・cronメタデータを既知の構成と比較する。
- 更新情報の鮮度、未適用更新、再起動要求を確認する。
- 未取得項目は未確認のまま残す。不審な場合はこのレポートだけで侵入を否定しない。

## Collection status

| ID | Status | Exit code | Check |
| --- | --- | --- | --- |
NOTES
  awk -F '\t' 'NR>1 {printf "| %s | %s | %s | %s |\n", $1,$2,$3,$4}' "$INDEX"
  printf '\n## Evidence\n'
  while IFS=$'\t' read -r id status rc title; do
    [[ $id == id ]] && continue
    printf '\n### %s: %s\n\nStatus: %s; exit code: %s\n\n' "$id" "$title" "$status" "$rc"
    # Remove terminal escape/control bytes from the presentation, preserving raw evidence locally.
    LC_ALL=C sed 's/[^[:print:]\t]//g; s/^/    /' "$DEST/evidence/$id.txt"
    printf '\n'
  done < "$INDEX"
} > "$REPORT" || die 'Markdown generation failed'

if [[ $FORMAT == both ]]; then
  python3 - "$DEST" <<'PY' || exit 2
import csv, html, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
esc = html.escape
def safe(text):
    return esc(re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', text))
rows = list(csv.DictReader((root / 'checks.tsv').open(encoding='utf-8'), delimiter='\t'))
intro = (root / 'report.md').read_text(encoding='utf-8', errors='replace').split('## Collection status')[0]
out = ['<!doctype html><html lang="ja"><meta charset="utf-8">',
       '<meta name="viewport" content="width=device-width, initial-scale=1">',
       '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
       '<title>Ubuntu Security Check</title><style>',
       'body{font:16px/1.6 system-ui,sans-serif;margin:2rem auto;padding:0 1rem;max-width:1100px;background:#101923;color:#e4edf5}',
       'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#172533;padding:1rem;border-radius:8px}',
       'table{border-collapse:collapse;width:100%}td,th{padding:.5rem;text-align:left;border-bottom:1px solid #526273}',
       'details{margin:1rem 0}summary{cursor:pointer}a{color:#a2d3ff}.incomplete{color:#ffd28a}',
       '</style><h1>Ubuntu Security Check</h1><p>Evidence collection / 診断証跡。安全性の合格判定ではありません。</p>',
       '<pre>' + safe(intro) + '</pre><h2>Collection status</h2><table><tr><th>Check</th><th>Status</th><th>Exit</th></tr>']
for row in rows:
    state = esc(row['status'])
    out.append('<tr><td><a href="#' + esc(row['id']) + '">' + esc(row['title']) + '</a></td><td>' + state + '</td><td>' + esc(row['exit_code']) + '</td></tr>')
out.append('</table><h2>Evidence</h2>')
for row in rows:
    content = (root / 'evidence' / (row['id'] + '.txt')).read_text(encoding='utf-8', errors='replace')
    out.append('<details id="' + esc(row['id']) + '"><summary>' + esc(row['title']) + ' — ' + esc(row['status']) + '</summary><pre>' + safe(content) + '</pre></details>')
out.append('</html>')
(root / 'report.html').write_text('\n'.join(out), encoding='utf-8')
PY
fi
# A checksum detects later accidental modification, not tampering by a compromised root.
(cd -- "$DEST" && sha256sum report.md checks.tsv evidence/*.txt > SHA256SUMS) || die 'Checksum generation failed'
if [[ $FORMAT == both ]]; then (cd -- "$DEST" && sha256sum report.html >> SHA256SUMS) || die 'HTML checksum failed'; fi
if (( WANT_ZIP )); then
  python3 - "$DEST" <<'PY' || exit 2
import os, pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
target = root.with_name(root.name + '.zip')
# x refuses existing archives, including symlinks. umask is inherited from Bash.
with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_DEFLATED) as z:
    for path in sorted(root.rglob('*')):
        if path.is_file() and not path.is_symlink():
            z.write(path, arcname=str(path.relative_to(root.parent)))
os.chmod(target, 0o600)
print('ZIP: ' + str(target))
PY
fi
printf '\nReport: %s\n' "$REPORT"
[[ $FORMAT == both ]] && printf 'HTML: %s/report.html\n' "$DEST"
INCOMPLETE=$(awk -F '\t' 'NR>1 && $2 != "COLLECTED" {n++} END {print n+0}' "$INDEX")
printf 'Incomplete checks: %s (see checks.tsv)\nNo safety/compromise verdict is issued.\n' "$INCOMPLETE"
(( INCOMPLETE == 0 )) || exit 1
exit 0
