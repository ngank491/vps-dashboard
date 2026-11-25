#!/usr/bin/env bash
# Cài đặt / cập nhật vpsmon. Chạy lại bất cứ lúc nào để cập nhật code hoặc luật firewalld.
#   sudo ./install.sh
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX=/opt/vpsmon
CONF_DIR=/etc/vpsmon
CONF="$CONF_DIR/vpsmon.env"
UNIT=/etc/systemd/system/vpsmon.service

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Cần chạy bằng root: sudo $0"
command -v systemctl >/dev/null || die "Cần systemd."
command -v python3 >/dev/null || die "Cần python3 (>= 3.6)."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' || die "Cần python3 >= 3.6."

# ---- file chương trình
say "Cài file vào $PREFIX"
install -d -m 755 "$PREFIX"
install -m 644 "$SRC/vpsmon/vpsmon.py" "$SRC/vpsmon/index.html" "$PREFIX/"
install -d -m 755 /var/lib/vpsmon

# ---- cấu hình (không ghi đè nếu đã có)
install -d -m 755 "$CONF_DIR"
if [ ! -f "$CONF" ]; then
  wan=$(awk '$2=="00000000" {print $1; exit}' /proc/net/route)
  sed "s/^VPSMON_WAN_IF=.*/VPSMON_WAN_IF=${wan}/" "$SRC/vpsmon.env.example" > "$CONF"
  chmod 640 "$CONF"
  say "Tạo cấu hình $CONF (card mạng: ${wan:-?}) — hãy xem lại cho đúng với máy của bạn"
else
  say "Giữ nguyên cấu hình $CONF"
fi

# đọc các giá trị cần cho luật tường lửa
set -a; . "$CONF"; set +a
WAN="${VPSMON_WAN_IF:-$(awk '$2=="00000000" {print $1; exit}' /proc/net/route)}"
GROUP="${VPSMON_NFLOG_GROUP:-7}"
TCPI="${VPSMON_TCP_IGNORE:-}"
UDPI="${VPSMON_UDP_IGNORE:-}"

# ---- luật NFLOG trong firewalld: ghi nhận gói mới vào cổng WAN (trừ cổng bỏ qua), có giới hạn tốc độ
rule() { # $1=tcp|udp $2=ignore-list
  local r="-i $WAN -p $1 -m conntrack --ctstate NEW"
  [ -n "$2" ] && r="$r -m multiport ! --dports $2"
  echo "$r -m limit --limit 200/second --limit-burst 400 -j NFLOG --nflog-group $GROUP --nflog-range 80"
}
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  say "Luật NFLOG firewalld (card $WAN, nhóm $GROUP)"
  # xoá luật vpsmon cũ của nhóm này nếu khác cấu hình hiện tại
  for perm in "" "--permanent"; do
    for fam in ipv4 ipv6; do
      firewall-cmd $perm --direct --get-rules $fam filter INPUT 2>/dev/null | grep -- "--nflog-group $GROUP " | while read -r prio rest; do
        rest=$(printf '%s' "$rest" | tr -d "'")   # firewalld in '!' kèm dấu nháy
        if [ "$rest" != "$(rule tcp "$TCPI")" ] && [ "$rest" != "$(rule udp "$UDPI")" ]; then
          firewall-cmd $perm --direct --remove-rule $fam filter INPUT "$prio" $rest >/dev/null
        fi
      done
      for spec in "$(rule tcp "$TCPI")" "$(rule udp "$UDPI")"; do
        firewall-cmd $perm --direct --query-rule $fam filter INPUT 0 $spec >/dev/null 2>&1 \
          || firewall-cmd $perm --direct --add-rule $fam filter INPUT 0 $spec >/dev/null
      done
    done
  done
else
  warn "Không thấy firewalld đang chạy: bỏ qua ghi nhận quét cổng; nút Chặn IP sẽ không hoạt động."
fi

# ---- systemd
say "Cài dịch vụ systemd vpsmon"
install -m 644 "$SRC/vpsmon.service" "$UNIT"
systemctl daemon-reload
systemctl enable vpsmon >/dev/null 2>&1
systemctl restart vpsmon

for i in $(seq 1 20); do
  if command -v curl >/dev/null && curl -sf "http://${VPSMON_LISTEN:-127.0.0.1:8790}/api/data" -o /dev/null; then
    ok=1; break
  fi
  sleep 1
done
if [ "${ok:-0}" = 1 ]; then
  say "vpsmon đang chạy tại http://${VPSMON_LISTEN:-127.0.0.1:8790}/"
else
  warn "Chưa kiểm tra được trang web; xem log: journalctl -u vpsmon -n 50"
fi

cat <<EOF

Dashboard chỉ nghe nội bộ. Cách truy cập an toàn:
  * SSH tunnel:  ssh -L 8790:127.0.0.1:8790 user@VPS   rồi mở http://localhost:8790/
  * Hoặc Caddy chỉ cho Tailscale: xem examples/Caddyfile
Cấu hình: $CONF   (sửa xong: systemctl restart vpsmon)
EOF
