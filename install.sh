#!/usr/bin/env bash
# Install / update vpsmon. Safe to re-run any time (updates code and firewalld rules).
# Cài đặt / cập nhật vpsmon. Chạy lại bất cứ lúc nào.
#   sudo ./install.sh
# Messages are in Vietnamese when LANG starts with "vi", otherwise English.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX=/opt/vpsmon
CONF_DIR=/etc/vpsmon
CONF="$CONF_DIR/vpsmon.env"
UNIT=/etc/systemd/system/vpsmon.service

case "${LC_ALL:-${LANG:-}}" in vi*) VI=1 ;; *) VI=0 ;; esac
m()    { if [ "$VI" = 1 ]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }   # m "tiếng Việt" "English"
say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "$(m "Cần chạy bằng root: sudo $0" "Must run as root: sudo $0")"
command -v systemctl >/dev/null || die "$(m "Cần systemd." "systemd is required.")"
command -v python3 >/dev/null || die "$(m "Cần python3 (>= 3.6)." "python3 (>= 3.6) is required.")"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' || die "$(m "Cần python3 >= 3.6." "python3 >= 3.6 is required.")"

# ---- program files
say "$(m "Cài file vào $PREFIX" "Installing files to $PREFIX")"
install -d -m 755 "$PREFIX"
install -m 644 "$SRC/vpsmon/vpsmon.py" "$SRC/vpsmon/index.html" "$PREFIX/"
install -d -m 755 /var/lib/vpsmon

# ---- config (never overwritten)
install -d -m 755 "$CONF_DIR"
if [ ! -f "$CONF" ]; then
  wan=$(awk '$2=="00000000" {print $1; exit}' /proc/net/route)
  sed "s/^VPSMON_WAN_IF=.*/VPSMON_WAN_IF=${wan}/" "$SRC/vpsmon.env.example" > "$CONF"
  chmod 640 "$CONF"
  say "$(m "Tạo cấu hình $CONF (card mạng: ${wan:-?}) — hãy xem lại cho đúng với máy của bạn" \
           "Created config $CONF (network interface: ${wan:-?}) — please review it for your machine")"
else
  say "$(m "Giữ nguyên cấu hình $CONF" "Keeping existing config $CONF")"
fi

# values needed for the firewall rules
set -a; . "$CONF"; set +a
WAN="${VPSMON_WAN_IF:-$(awk '$2=="00000000" {print $1; exit}' /proc/net/route)}"
GROUP="${VPSMON_NFLOG_GROUP:-7}"
TCPI="${VPSMON_TCP_IGNORE:-}"
UDPI="${VPSMON_UDP_IGNORE:-}"

# ---- firewalld NFLOG rules: record new packets on the WAN interface (except ignored ports), rate-limited
rule() { # $1=tcp|udp $2=ignore-list
  local r="-i $WAN -p $1 -m conntrack --ctstate NEW"
  [ -n "$2" ] && r="$r -m multiport ! --dports $2"
  echo "$r -m limit --limit 200/second --limit-burst 400 -j NFLOG --nflog-group $GROUP --nflog-range 80"
}
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  say "$(m "Luật NFLOG firewalld (card $WAN, nhóm $GROUP)" "firewalld NFLOG rules (interface $WAN, group $GROUP)")"
  for perm in "" "--permanent"; do
    for fam in ipv4 ipv6; do
      # remove old vpsmon rules of this group that no longer match the config
      firewall-cmd $perm --direct --get-rules $fam filter INPUT 2>/dev/null | grep -- "--nflog-group $GROUP " | while read -r prio rest; do
        rest=$(printf '%s' "$rest" | tr -d "'")   # firewalld prints '!' with quotes
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
  warn "$(m "Không thấy firewalld đang chạy: bỏ qua ghi nhận quét cổng; nút Chặn IP sẽ không hoạt động." \
            "firewalld is not running: port-scan capture skipped; the Block IP button will not work.")"
fi

# ---- systemd
say "$(m "Cài dịch vụ systemd vpsmon" "Installing systemd service vpsmon")"
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
  say "$(m "vpsmon đang chạy tại" "vpsmon is running at") http://${VPSMON_LISTEN:-127.0.0.1:8790}/"
else
  warn "$(m "Chưa kiểm tra được trang web; xem log:" "Could not reach the web page yet; check the log:") journalctl -u vpsmon -n 50"
fi

if [ "$VI" = 1 ]; then cat <<EOF

Dashboard chỉ nghe nội bộ. Cách truy cập an toàn:
  * SSH tunnel:  ssh -L 8790:127.0.0.1:8790 user@VPS   rồi mở http://localhost:8790/
  * Hoặc Caddy chỉ cho Tailscale: xem examples/Caddyfile
Cấu hình: $CONF   (sửa xong: systemctl restart vpsmon)
Giao diện có tiếng Việt / English (nút VI | EN ở góc trên).
EOF
else cat <<EOF

The dashboard listens on localhost only. To reach it safely:
  * SSH tunnel:  ssh -L 8790:127.0.0.1:8790 user@VPS   then open http://localhost:8790/
  * Or Caddy restricted to Tailscale: see examples/Caddyfile
Config: $CONF   (after editing: systemctl restart vpsmon)
The UI is available in English / Tiếng Việt (VI | EN switch, top right).
EOF
fi
