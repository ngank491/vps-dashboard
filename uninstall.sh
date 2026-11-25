#!/usr/bin/env bash
# Uninstall vpsmon / Gỡ vpsmon.
#   sudo ./uninstall.sh          keep data and config / giữ dữ liệu và cấu hình
#   sudo ./uninstall.sh --purge  also delete /var/lib/vpsmon and /etc/vpsmon / xoá luôn dữ liệu và cấu hình
# Blocked IPs are NOT unblocked (firewalld zone drop is left as is).
# Các IP đã chặn vẫn giữ nguyên trong zone drop của firewalld.
set -euo pipefail

case "${LC_ALL:-${LANG:-}}" in vi*) VI=1 ;; *) VI=0 ;; esac
m() { if [ "$VI" = 1 ]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }

[ "$(id -u)" -eq 0 ] || { echo "$(m "Cần chạy bằng root: sudo $0" "Must run as root: sudo $0")" >&2; exit 1; }

GROUP=7
[ -f /etc/vpsmon/vpsmon.env ] && GROUP=$(. /etc/vpsmon/vpsmon.env; echo "${VPSMON_NFLOG_GROUP:-7}")

systemctl disable --now vpsmon 2>/dev/null || true
rm -f /etc/systemd/system/vpsmon.service
systemctl daemon-reload

if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  for perm in "" "--permanent"; do
    for fam in ipv4 ipv6; do
      firewall-cmd $perm --direct --get-rules $fam filter INPUT 2>/dev/null | grep -- "--nflog-group $GROUP " | while read -r prio rest; do
        rest=$(printf '%s' "$rest" | tr -d "'")   # firewalld prints '!' with quotes
        firewall-cmd $perm --direct --remove-rule $fam filter INPUT "$prio" $rest >/dev/null \
          && echo "$(m "Đã xoá luật NFLOG" "Removed NFLOG rule") ($fam${perm:+, permanent})"
      done
    done
  done
fi

rm -rf /opt/vpsmon
if [ "${1:-}" = "--purge" ]; then
  rm -rf /var/lib/vpsmon /etc/vpsmon
  echo "$(m "Đã xoá dữ liệu và cấu hình." "Data and config deleted.")"
fi
echo "$(m "Đã gỡ vpsmon." "vpsmon uninstalled.")"
