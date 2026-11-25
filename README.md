# vps-dashboard (vpsmon)

Dashboard nhỏ gọn để theo dõi một VPS Linux: tài nguyên, dịch vụ, kết nối, **bot quét cổng và bot dò mật khẩu proxy**, kèm nút chặn IP ngay trên trang.

- **Một file Python duy nhất**, chỉ dùng thư viện chuẩn (Python ≥ 3.6), không cần pip, Docker hay database server.
- **Nhẹ**: khoảng 16–20 MB RAM, database SQLite vài MB, tự xoá dữ liệu cũ.
- Lượt quét được thu bằng **NFLOG** nên không ghi vào journal hay syslog, log hệ thống không bị phình.
- Chạy tốt trên **CentOS 7** (Python 3.6, systemd 219, kernel 3.10) và các bản mới hơn có firewalld.

*English summary at the bottom.*

## Tính năng

| Mục | Nội dung |
|---|---|
| Cảnh báo | Dịch vụ bị dừng, chứng chỉ HTTPS sắp hết hạn, ổ đĩa/RAM/swap đầy, tải CPU cao, ổ mạng mất kết nối |
| Tài nguyên | CPU, RAM, swap, ổ đĩa, tốc độ mạng, biểu đồ 24 giờ / 7 ngày |
| Dịch vụ | Trạng thái, thời gian chạy, CPU, RAM, cổng đang nghe của từng dịch vụ; đánh dấu cổng **mở ra Internet**, cổng nội bộ, cổng chỉ qua Tailscale |
| Kết nối | Người đang dùng proxy, peer WireGuard (bắt tay cuối, dung lượng), máy trong Tailscale (trực tiếp hay qua relay) |
| Tấn công | Biểu đồ theo giờ/ngày, cổng bị quét nhiều nhất, IP quét nhiều nhất, IP dò mật khẩu proxy, sự kiện gần đây |
| Quốc gia | Cờ và tên nước cạnh mọi IP (DB-IP Lite, tra ngay trên máy, không gửi IP ra ngoài) |
| Chặn IP | Nút **Chặn / Bỏ chặn** → firewalld zone `drop` (runtime + permanent) |

## Yêu cầu

- Linux có **systemd** và **python3 ≥ 3.6**
- **firewalld** đang chạy (để ghi nhận quét cổng và chặn IP; thiếu thì các phần khác vẫn chạy)
- Tuỳ chọn: proxy [gost v3](https://github.com/go-gost/gost) (đọc log lỗi xác thực), WireGuard (`wg`), Tailscale, Caddy

## Cài đặt

```bash
git clone https://github.com/ngank491/vps-dashboard.git
cd vps-dashboard
sudo ./install.sh
```

Script sẽ:
1. chép chương trình vào `/opt/vpsmon`,
2. tạo cấu hình `/etc/vpsmon/vpsmon.env` (nếu chưa có, tự nhận diện card mạng),
3. thêm 4 luật NFLOG vào firewalld (IPv4/IPv6 × TCP/UDP) — **chỉ ghi nhận, không chặn hay mở cổng nào**,
4. cài và khởi động dịch vụ `vpsmon` (nghe `127.0.0.1:8790`).

Chạy lại `sudo ./install.sh` để cập nhật code hoặc sau khi đổi cấu hình tường lửa trong file env.

## Cấu hình

Sửa `/etc/vpsmon/vpsmon.env` rồi `sudo systemctl restart vpsmon`. Các mục quan trọng (xem đầy đủ trong [vpsmon.env.example](vpsmon.env.example)):

| Biến | Ý nghĩa |
|---|---|
| `VPSMON_TCP_IGNORE`, `VPSMON_UDP_IGNORE` | Cổng dịch vụ công khai hợp lệ, không tính là "quét" (ví dụ `80,443`) |
| `VPSMON_PROXY_PORTS` | Cổng proxy cần theo dõi, dạng `21080:SOCKS5,23128:HTTP` |
| `VPSMON_PROXY_UNIT` | systemd unit của proxy gost (để trống nếu không dùng) |
| `VPSMON_SERVICES` | Dịch vụ chính hiển thị đầu bảng |
| `VPSMON_OWN_IPS` | **IP public của VPS nếu VPS nằm sau NAT** (Oracle, AWS, GCP…) — để nút Chặn không chặn nhầm chính mình |
| `VPSMON_NAS_PATH` | Thư mục ổ mạng cần theo dõi dung lượng (tuỳ chọn) |
| `VPSMON_GEOIP` | `1` = hiện quốc gia (tự tải ~8 MB, cập nhật hằng tháng), `0` = tắt |

Đặt tên cho peer WireGuard: thêm dòng chú thích ngay trên `[Peer]` trong `/etc/wireguard/wg0.conf`, ví dụ `# Laptop`.

## Truy cập an toàn

Dashboard **chỉ nghe localhost và không có đăng nhập** — đừng mở thẳng ra Internet. Chọn một trong hai cách:

- **SSH tunnel**: `ssh -L 8790:127.0.0.1:8790 user@vps` rồi mở <http://localhost:8790/>
- **Caddy chỉ cho Tailscale**: xem [examples/Caddyfile](examples/Caddyfile) → `https://<may>.<tailnet>.ts.net/monitor/`

## Bảo mật

- Dịch vụ chạy bằng root nhưng bị giới hạn chỉ còn các quyền `CAP_NET_ADMIN` (NFLOG, `wg`), `CAP_DAC_READ_SEARCH` (đọc chứng chỉ), `CAP_SYS_PTRACE` (chỉ đọc `/proc/PID/fd` để biết cổng thuộc dịch vụ nào); `ProtectSystem=full`, `ProtectHome`, `NoNewPrivileges`, giới hạn 80 MB RAM.
- Khoá bí mật WireGuard không bao giờ được gửi lên trang.
- API chặn IP (`POST /api/block`):
  - chỉ nhận JSON có header riêng `X-Vpsmon: 1` và `Origin` trùng host (chống trang khác gửi lệnh thay bạn — CSRF),
  - chỉ chặn **từng IP**, kiểm tra đúng định dạng,
  - **từ chối** IP của chính VPS, dải nội bộ/Tailscale/đặc biệt, và IP mạng của các máy trong Tailscale/WireGuard (tự ghi nhớ, ví dụ mạng nhà),
  - thêm vào firewalld runtime + permanent, **không** `--reload`; mỗi thao tác được ghi vào `journalctl -u vpsmon`.

## Gỡ cài đặt

```bash
sudo ./uninstall.sh           # giữ dữ liệu và cấu hình
sudo ./uninstall.sh --purge   # xoá luôn dữ liệu và cấu hình
```

Các IP đã chặn vẫn nằm trong zone `drop` của firewalld.

## Giới hạn

- Chỉ thấy gói tin thực sự tới được VPS: nếu nhà cung cấp (ví dụ Security List của Oracle) chặn trước thì không đếm được.
- Gói tin bị giới hạn 200 gói/giây để chống lụt; khi bị tấn công dồn dập, số liệu là ước lượng thấp.
- Quốc gia là nơi đăng ký dải IP (thường là nơi đặt máy chủ thuê), không phải vị trí người điều khiển bot.
- Log lỗi xác thực proxy hiện hỗ trợ định dạng JSON của gost v3.

## Giấy phép

MIT — xem [LICENSE](LICENSE).

Dữ liệu quốc gia: [IP Geolocation by DB-IP](https://db-ip.com), giấy phép [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (tải về khi chạy, không kèm trong repo).

---

## English summary

**vpsmon** is a tiny single-file VPS dashboard (Python ≥ 3.6 stdlib only, ~16–20 MB RAM) that shows resources, systemd services with their listening ports (flagging ports exposed to the Internet), WireGuard / Tailscale / proxy connections, and **port-scan and proxy brute-force activity** captured via firewalld NFLOG rules (nothing is written to the journal). IPs get a country flag from the DB-IP Lite database (offline lookups), and can be blocked/unblocked from the page (firewalld `drop` zone, with CSRF protection and safeguards against blocking your own or home IPs).

Install: `sudo ./install.sh`, configure `/etc/vpsmon/vpsmon.env`, then reach it through an SSH tunnel or a reverse proxy restricted to your private network (see `examples/Caddyfile`). It listens on localhost only and has no login — do not expose it publicly. Works on CentOS 7 and newer firewalld-based distros. MIT licensed.
