#!/usr/bin/env bash
# Gỡ vpsmon.   sudo ./uninstall.sh          (giữ dữ liệu và cấu hình)
#              sudo ./uninstall.sh --purge  (xoá luôn /var/lib/vpsmon và /etc/vpsmon)
# Không bỏ chặn các IP đã chặn (zone drop của firewalld vẫn giữ nguyên).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Cần chạy bằng root: sudo $0" >&2; exit 1; }

GROUP=7
[ -f /etc/vpsmon/vpsmon.env ] && GROUP=$(. /etc/vpsmon/vpsmon.env; echo "${VPSMON_NFLOG_GROUP:-7}")

systemctl disable --now vpsmon 2>/dev/null || true
rm -f /etc/systemd/system/vpsmon.service
systemctl daemon-reload

if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  for perm in "" "--permanent"; do
    for fam in ipv4 ipv6; do
      firewall-cmd $perm --direct --get-rules $fam filter INPUT 2>/dev/null | grep -- "--nflog-group $GROUP " | while read -r prio rest; do
        rest=$(printf '%s' "$rest" | tr -d "'")   # firewalld in '!' kèm dấu nháy
        firewall-cmd $perm --direct --remove-rule $fam filter INPUT "$prio" $rest >/dev/null && echo "Đã xoá luật NFLOG ($fam${perm:+, permanent})"
      done
    done
  done
fi

rm -rf /opt/vpsmon
if [ "${1:-}" = "--purge" ]; then
  rm -rf /var/lib/vpsmon /etc/vpsmon
  echo "Đã xoá dữ liệu và cấu hình."
fi
echo "Đã gỡ vpsmon."
