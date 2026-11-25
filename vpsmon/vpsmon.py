#!/usr/bin/env python3
"""vpsmon - dashboard nhỏ gọn theo dõi VPS (Python >= 3.6, chỉ dùng thư viện chuẩn).

Nguồn dữ liệu:
  - NFLOG (firewalld direct rules do install.sh tạo): gói TCP/UDP mới vào cổng mạng WAN,
    trừ các cổng dịch vụ công khai -> cổng proxy = "proxy", cổng khác = "scan". Không ghi vào journal.
  - journalctl -u <proxy unit> (gost v3, log JSON): lỗi xác thực / lỗi bắt tay của proxy.
  - /proc, cgroup, systemctl, wg, tailscale, firewall-cmd: tài nguyên, dịch vụ, kết nối.
Cấu hình: biến môi trường VPSMON_* (xem vpsmon.env.example). Web chỉ nghe localhost,
hãy đặt sau reverse proxy có giới hạn truy cập (ví dụ Caddy chỉ cho Tailscale).
"""
import collections
import glob
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

def _env(key, default=""):
    return os.environ.get("VPSMON_" + key, default).strip()


def _default_iface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:
                    return p[0]
    except OSError:
        pass
    return "eth0"


def _parse_ports(v):
    out = {}
    for item in v.split(","):
        if item.strip():
            port, _, label = item.strip().partition(":")
            out[int(port)] = label or "proxy"
    return out


_host, _, _port = _env("LISTEN", "127.0.0.1:8790").rpartition(":")
LISTEN = (_host or "127.0.0.1", int(_port))
DB_PATH = _env("DB", "/var/lib/vpsmon/vpsmon.db")
DATA_DIR = os.path.dirname(DB_PATH)
HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
NFLOG_GROUP = int(_env("NFLOG_GROUP", "7"))
WAN_IF = _env("WAN_IF") or _default_iface()
PROXY_PORTS = _parse_ports(_env("PROXY_PORTS", "21080:SOCKS5,23128:HTTP"))
PROXY_UNIT = _env("PROXY_UNIT", "gost")           # systemd unit của proxy (đọc log lỗi xác thực); để trống = tắt
PROXY_USER = _env("PROXY_USER", PROXY_UNIT)       # user chạy proxy (đếm kết nối ra ngoài)
SERVICES = [x.strip() for x in _env("SERVICES", "sshd,firewalld,crond,chronyd," + PROXY_UNIT).split(",") if x.strip()]
NAS_PATH = _env("NAS_PATH")                       # thư mục ổ mạng cần theo dõi; để trống = tắt
WG_IFACE = _env("WG_IFACE", "wg0")
CERT_GLOB = _env("CERT_GLOB", "/var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt")
GEOIP = _env("GEOIP", "1") not in ("0", "no", "false", "")
KEEP_HITS_DAYS = 30
KEEP_METRICS_DAYS = 7
KEEP_RECENT = 1000

lock = threading.Lock()
pending = collections.Counter()      # (hour, ip, proto, port, kind) -> n
pending_recent = []                  # (ts, kind, ip, proto, port, msg)
recent_seen = {}                     # (ip, port, kind) -> last ts ghi vào "recent"
state = {"blocked": [], "blocked_at": 0, "nflog": "chưa chạy", "proxylog": "chưa chạy" if PROXY_UNIT else "tắt"}


def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS hits(hour INTEGER, ip TEXT, proto TEXT, port INTEGER,
        kind TEXT, n INTEGER, PRIMARY KEY(hour, ip, proto, port, kind));
    CREATE INDEX IF NOT EXISTS hits_kind_hour ON hits(kind, hour);
    CREATE TABLE IF NOT EXISTS ipseen(ip TEXT PRIMARY KEY, first INTEGER, last INTEGER);
    CREATE TABLE IF NOT EXISTS recent(ts REAL, kind TEXT, ip TEXT, proto TEXT, port INTEGER, msg TEXT);
    CREATE INDEX IF NOT EXISTS recent_ts ON recent(ts);
    CREATE TABLE IF NOT EXISTS metrics(ts INTEGER PRIMARY KEY, cpu REAL, mem REAL, swap REAL,
        disk REAL, load REAL, rx REAL, tx REAL);
    CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
    """)
    con.commit()
    con.close()


def record(ts, kind, ip, proto, port, msg=""):
    hour = int(ts) // 3600 * 3600
    key = (ip, port, kind)
    with lock:
        pending[(hour, ip, proto, port, kind)] += 1
        last = recent_seen.get(key, 0)
        if ts - last >= 60:          # gộp: mỗi (IP, cổng, loại) tối đa 1 dòng/phút trong "recent"
            recent_seen[key] = ts
            pending_recent.append((ts, kind, ip, proto, port, msg))


# ---------------------------------------------------------------- NFLOG reader
def nl_attr(atype, data):
    ln = 4 + len(data)
    return struct.pack("=HH", ln, atype) + data + b"\0" * ((4 - ln % 4) % 4)


def nl_cfg(sock, seq, family, res_id, attrs):
    msg_type = (4 << 8) | 1                       # NFNL_SUBSYS_ULOG, NFULNL_MSG_CONFIG
    payload = struct.pack("=BBH", family, 0, socket.htons(res_id)) + attrs
    hdr = struct.pack("=IHHII", 16 + len(payload), msg_type, 1 | 4, seq, 0)  # REQUEST|ACK
    sock.send(hdr + payload)
    try:
        sock.recv(4096)                           # ACK hoặc lỗi (bỏ qua: PF_BIND có thể EEXIST)
    except OSError:
        pass


def parse_ip_packet(p):
    if not p:
        return None
    ver = p[0] >> 4
    if ver == 4 and len(p) >= 20:
        ihl = (p[0] & 15) * 4
        proto = p[9]
        src = socket.inet_ntop(socket.AF_INET, p[12:16])
        off = ihl
    elif ver == 6 and len(p) >= 40:
        proto = p[6]
        src = socket.inet_ntop(socket.AF_INET6, p[8:24])
        off = 40
    else:
        return None
    if proto in (6, 17) and len(p) >= off + 4:
        dport = struct.unpack("!H", p[off + 2:off + 4])[0]
        return src, ("tcp" if proto == 6 else "udp"), dport
    return None


def nflog_loop():
    while True:
        try:
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)  # NETLINK_NETFILTER
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            s.bind((0, 0))
            s.settimeout(2)
            for fam in (socket.AF_INET, socket.AF_INET6):
                nl_cfg(s, 1, fam, 0, nl_attr(1, struct.pack("B", 3)))          # PF_BIND
            nl_cfg(s, 2, 0, NFLOG_GROUP, nl_attr(1, struct.pack("B", 1)))      # BIND group
            nl_cfg(s, 3, 0, NFLOG_GROUP, nl_attr(2, struct.pack("!IBB", 80, 2, 0)))  # COPY_PACKET 80B
            s.settimeout(None)
            state["nflog"] = "đang chạy"
            while True:
                try:
                    data = s.recv(65536)
                except OSError as e:
                    if e.errno == 105:            # ENOBUFS: bị dồn gói, bỏ qua và tiếp tục
                        continue
                    raise
                now = time.time()
                pos = 0
                while pos + 16 <= len(data):
                    mlen, mtype = struct.unpack_from("=IH", data, pos)
                    if mlen < 16:
                        break
                    if mtype == (4 << 8):         # NFULNL_MSG_PACKET
                        a = pos + 20
                        end = pos + mlen
                        while a + 4 <= end:
                            alen, atype = struct.unpack_from("=HH", data, a)
                            if alen < 4:
                                break
                            if (atype & 0x7fff) == 9:   # NFULA_PAYLOAD
                                r = parse_ip_packet(data[a + 4:a + alen])
                                if r:
                                    src, proto, dport = r
                                    kind = "proxy" if (proto == "tcp" and dport in PROXY_PORTS) else "scan"
                                    record(now, kind, src, proto, dport)
                            a += (alen + 3) & ~3
                    pos += (mlen + 3) & ~3
        except Exception as e:
            state["nflog"] = "lỗi: %s" % e
            time.sleep(10)


# ---------------------------------------------------------------- proxy (gost v3) journal follower
def gost_loop():
    while True:
        try:
            con = db()
            row = con.execute("SELECT v FROM kv WHERE k='gost_cursor'").fetchone()
            con.close()
            cmd = ["journalctl", "-u", PROXY_UNIT, "-o", "json", "-f", "--no-pager"]
            cmd += ["--after-cursor=" + row[0]] if row else ["--since=-7d"]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            state["proxylog"] = "đang chạy"
            for line in p.stdout:
                try:
                    j = json.loads(line.decode("utf-8", "replace"))
                    cursor = j.get("__CURSOR")
                    msg = j.get("MESSAGE")
                    if isinstance(msg, list):     # journal lưu bytes dạng mảng số
                        msg = bytes(msg).decode("utf-8", "replace")
                    ts = int(j.get("__REALTIME_TIMESTAMP", "0")) / 1e6 or time.time()
                    if msg and msg.startswith("{"):
                        g = json.loads(msg)
                        if g.get("kind") == "handler" and g.get("remote") and g.get("level") in ("error", "warn"):
                            ip = g["remote"].rsplit(":", 1)[0].strip("[]")
                            port = int(g.get("local", ":0").rsplit(":", 1)[1] or 0)
                            text = g.get("msg", "")
                            kind = "authfail" if "auth" in text else "proxyerr"
                            record(ts, kind, ip, "tcp", port, text[:120])
                    if cursor:
                        with lock:
                            state["gost_cursor"] = cursor
                except Exception:
                    continue
            p.wait()
            state["proxylog"] = "journalctl thoát, khởi động lại"
        except Exception as e:
            state["proxylog"] = "lỗi: %s" % e
        time.sleep(10)


# ---------------------------------------------------------------- system metrics
def read_cpu():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), idle


def read_mem():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, val = line.split(":")
            m[k] = int(val.split()[0]) * 1024
    avail = m.get("MemAvailable", m["MemFree"] + m.get("Cached", 0))
    return m["MemTotal"], m["MemTotal"] - avail, m["SwapTotal"], m["SwapTotal"] - m["SwapFree"]


def read_net():
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith(WAN_IF + ":"):
                v = line.split(":", 1)[1].split()
                return int(v[0]), int(v[8])
    return 0, 0


def read_disk():
    st = os.statvfs("/")
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    return total, total - free


def proxy_active():
    """Số kết nối ESTABLISHED đang mở vào cổng proxy (đang dùng proxy)."""
    n = 0
    ports = {"%04X" % p for p in PROXY_PORTS}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if parts[3] == "01" and parts[1].rsplit(":", 1)[1] in ports:
                        n += 1
        except OSError:
            pass
    return n


live = {}
nas = {"ok": None, "msg": "chưa kiểm tra", "path": NAS_PATH}


def nas_loop():
    """Kiểm tra ổ NAS mỗi 2 phút bằng tiến trình con có timeout, để NAS mất mạng không làm treo dashboard."""
    while True:
        try:
            r = subprocess.run(["timeout", "20", "stat", "-f", "-c", "%b %a %S %T", NAS_PATH],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            out = r.stdout.decode().split()
            if r.returncode == 0 and len(out) >= 4 and out[3] in ("cifs", "smb2", "UNKNOWN"):
                blocks, avail, bsize = int(out[0]), int(out[1]), int(out[2])
                nas.update(ok=True, total=blocks * bsize, used=(blocks - avail) * bsize,
                           msg="đã gắn", checked=time.time())
            elif r.returncode == 0:
                nas.update(ok=False, msg="chưa gắn (loại %s)" % (out[3] if len(out) > 3 else "?"), checked=time.time())
            else:
                nas.update(ok=False, msg="không truy cập được: " + (r.stderr.decode().strip()[-120:] or "timeout"),
                           checked=time.time())
        except Exception as e:
            nas.update(ok=False, msg="lỗi: %s" % e, checked=time.time())
        time.sleep(120)



def metrics_loop():
    prev_cpu = read_cpu()
    prev_net = read_net()
    prev_t = time.time()
    while True:
        time.sleep(60)
        try:
            cpu = read_cpu()
            net = read_net()
            t = time.time()
            dt_all = cpu[0] - prev_cpu[0]
            cpu_pct = 100.0 * (1 - (cpu[1] - prev_cpu[1]) / dt_all) if dt_all else 0
            rx = max(0, net[0] - prev_net[0]) / (t - prev_t)
            tx = max(0, net[1] - prev_net[1]) / (t - prev_t)
            prev_cpu, prev_net, prev_t = cpu, net, t
            mt, mu, st, su = read_mem()
            dt, du = read_disk()
            load = os.getloadavg()[0]
            live.update(cpu=cpu_pct, rx=rx, tx=tx)
            con = db()
            con.execute("INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?,?,?,?)",
                        (int(t), round(cpu_pct, 1), round(100.0 * mu / mt, 1),
                         round(100.0 * su / st, 1) if st else 0, round(100.0 * du / dt, 1),
                         round(load, 2), round(rx), round(tx)))
            con.commit()
            con.close()
        except Exception:
            pass


# ---------------------------------------------------------------- flush & housekeeping
def refresh_blocked():
    try:
        out = subprocess.check_output(["firewall-cmd", "--zone=drop", "--list-sources"],
                                      stderr=subprocess.DEVNULL, timeout=20).decode().split()
        state["blocked"] = out
    except Exception:
        pass
    refresh_public_ports()
    state["blocked_at"] = time.time()


def flush_loop():
    last_prune = 0
    while True:
        time.sleep(15)
        with lock:
            items = list(pending.items())
            pending.clear()
            rec = pending_recent[:]
            del pending_recent[:]
            cursor = state.pop("gost_cursor", None)
        try:
            con = db()
            for (hour, ip, proto, port, kind), n in items:
                cur = con.execute("UPDATE hits SET n=n+? WHERE hour=? AND ip=? AND proto=? AND port=? AND kind=?",
                                  (n, hour, ip, proto, port, kind))
                if cur.rowcount == 0:
                    con.execute("INSERT INTO hits VALUES(?,?,?,?,?,?)", (hour, ip, proto, port, kind, n))
                con.execute("INSERT OR IGNORE INTO ipseen VALUES(?,?,?)", (ip, hour, hour))
                con.execute("UPDATE ipseen SET last=MAX(last, ?) WHERE ip=?", (hour, ip))
            if rec:
                con.executemany("INSERT INTO recent VALUES(?,?,?,?,?,?)", rec)
                for r in rec:
                    con.execute("UPDATE ipseen SET last=MAX(last, ?) WHERE ip=?", (int(r[0]), r[2]))
            if cursor:
                con.execute("INSERT OR REPLACE INTO kv VALUES('gost_cursor', ?)", (cursor,))
            now = time.time()
            if now - last_prune > 3600:
                last_prune = now
                con.execute("DELETE FROM hits WHERE hour < ?", (now - KEEP_HITS_DAYS * 86400,))
                con.execute("DELETE FROM metrics WHERE ts < ?", (now - KEEP_METRICS_DAYS * 86400,))
                con.execute("DELETE FROM ipseen WHERE last < ?", (now - KEEP_HITS_DAYS * 86400,))
                con.execute("DELETE FROM recent WHERE ts < (SELECT ts FROM recent ORDER BY ts DESC LIMIT 1 OFFSET ?)",
                            (KEEP_RECENT,))
                with lock:
                    for k in [k for k, v in recent_seen.items() if now - v > 120]:
                        del recent_seen[k]
            con.commit()
            con.close()
        except Exception:
            pass
        if time.time() - state["blocked_at"] > 300:
            refresh_blocked()


# ---------------------------------------------------------------- services & connections
CLK_TCK = os.sysconf("SC_CLK_TCK")
CORE_UNITS = SERVICES + ["vpsmon"]
svc_prev = {}                        # unit -> (time, cpu_ticks)
svc_cache = {"t": 0, "data": None}
WG_CONF = "/etc/wireguard/%s.conf" % WG_IFACE


def _hex_addr(h):
    ip_hex, port_hex = h.split(":")
    port = int(port_hex, 16)
    b = bytes.fromhex(ip_hex)
    if len(b) == 4:
        ip = socket.inet_ntop(socket.AF_INET, b[::-1])
    else:  # IPv6: 4 nhóm 32-bit little-endian
        ip = socket.inet_ntop(socket.AF_INET6, b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4)))
    return ip, port


def read_sockets():
    """Trả về (listen: inode -> (proto, ip, port), established tcp list)."""
    listen, est = {}, []
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6")):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    p = line.split()
                    st, inode = p[3], p[9]
                    if proto == "tcp" and st == "0A" or proto == "udp" and st == "07":
                        ip, port = _hex_addr(p[1])
                        if inode != "0":
                            listen[inode] = (proto, ip, port)
                    elif proto == "tcp" and st == "01":
                        lip, lport = _hex_addr(p[1])
                        rip, rport = _hex_addr(p[2])
                        est.append((lip, lport, rip, rport, int(p[7])))
        except OSError:
            pass
    return listen, est


def ip_scope(ip):
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    if ip in ("0.0.0.0", "::"):
        return "all"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.is_loopback:
        return "local"
    if a in ipaddress.ip_network("100.64.0.0/10") or a in ipaddress.ip_network("fd7a:115c:a1e0::/48"):
        return "tailscale"
    return ip


def pid_stats(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            rest = f.read().rsplit(")", 1)[1].split()
        ticks = int(rest[11]) + int(rest[12])        # utime + stime
        start = int(rest[19])                        # starttime (ticks từ lúc boot)
        rss = 0
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024
                    break
        inodes = set()
        try:
            for fd in os.listdir("/proc/%d/fd" % pid):
                try:
                    l = os.readlink("/proc/%d/fd/%s" % (pid, fd))
                    if l.startswith("socket:["):
                        inodes.add(l[8:-1])
                except OSError:
                    continue
        except OSError:
            pass
        return ticks, start, rss, inodes
    except (OSError, IndexError, ValueError):
        return None


def services_detail():
    now = time.time()
    if svc_cache["data"] and now - svc_cache["t"] < 15:
        return svc_cache["data"]
    try:
        out = subprocess.run(["systemctl", "list-units", "--all", "-t", "service,socket,automount",
                              "--no-legend", "--plain"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10).stdout.decode()
    except Exception:
        out = ""
    units = {}
    for line in out.splitlines():
        p = line.split(None, 4)
        if len(p) >= 4:
            units[p[0]] = {"load": p[1], "active": p[2], "sub": p[3], "desc": p[4] if len(p) > 4 else ""}
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    boot = now - uptime
    listen, _ = read_sockets()
    public = set(state.get("public_ports", []))
    wg_port = state.get("wg_port")
    core_ids = []
    for c in CORE_UNITS:
        core_ids.append(c if "." in c else c + ".service")
    rows = []
    for uid, u in units.items():
        core = uid in core_ids
        if not core and not (uid.endswith(".service") and u["sub"] == "running"):
            continue
        name = uid[:-8] if uid.endswith(".service") else uid
        row = {"name": name, "desc": u["desc"], "active": u["active"], "sub": u["sub"], "core": core,
               "since": None, "rss": 0, "procs": 0, "cpu": None, "ports": []}
        ports = set()
        cg = "/sys/fs/cgroup/systemd/system.slice/%s/cgroup.procs" % uid
        ticks_total, starts = 0, []
        try:
            with open(cg) as f:
                pids = [int(x) for x in f.read().split()]
        except OSError:
            pids = []
        for pid in pids:
            s = pid_stats(pid)
            if not s:
                continue
            ticks, start, rss, inodes = s
            ticks_total += ticks
            starts.append(start)
            row["rss"] += rss
            row["procs"] += 1
            for ino in inodes:
                if ino in listen:
                    ports.add(listen[ino])
        if starts:
            row["since"] = boot + min(starts) / CLK_TCK
            prev = svc_prev.get(uid)
            if prev and now > prev[0] and ticks_total >= prev[1]:
                row["cpu"] = round(100.0 * (ticks_total - prev[1]) / CLK_TCK / (now - prev[0]), 1)
            svc_prev[uid] = (now, ticks_total)
        if uid.startswith("wg-quick@") and wg_port:
            ports.add(("udp", "0.0.0.0", wg_port))
        if uid.endswith(".socket"):
            try:
                lo = subprocess.run(["systemctl", "show", uid, "-p", "Listen"], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=5).stdout.decode()
                for line in lo.splitlines():
                    v = line.split("=", 1)[1] if "=" in line else ""
                    if ":" in v:
                        ip, port = v.rsplit(":", 1)
                        ports.add(("udp" if "Datagram" in line else "tcp", ip.strip("[]"), int(port)))
            except Exception:
                pass
        seen = set()
        for proto, ip, port in sorted(ports, key=lambda x: (x[2], x[0])):
            sc = ip_scope(ip)
            key = (proto, port, sc)
            if key in seen:
                continue
            seen.add(key)
            row["ports"].append({"proto": proto, "port": port, "scope": sc,
                                 "public": sc not in ("local", "tailscale") and "%d/%s" % (port, proto) in public})
        rows.append(row)
    rows.sort(key=lambda r: (not r["core"], core_ids.index(r["name"] if "." in r["name"] else r["name"] + ".service")
                             if r["core"] else 0, -r["rss"]))
    svc_cache.update(t=now, data=rows)
    return rows


def wg_names():
    """Tên peer lấy từ dòng chú thích (# ...) ngay trên [Peer] hoặc '# Name = ...' trong file cấu hình WireGuard. Không đọc khoá bí mật ra ngoài."""
    names, pending_comment, in_peer, cur = {}, None, False, {}
    try:
        with open(WG_CONF) as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("#"):
                    c = line.lstrip("#").strip()
                    if in_peer and c.lower().startswith("name"):
                        cur["name"] = c.split("=", 1)[-1].split(":", 1)[-1].strip()
                    else:
                        pending_comment = c
                    continue
                if line.lower() == "[peer]":
                    if cur.get("key") and cur.get("name"):
                        names[cur["key"]] = cur["name"]
                    in_peer, cur = True, {"name": pending_comment} if pending_comment else {}
                    pending_comment = None
                elif line.startswith("["):
                    in_peer, pending_comment = False, None
                elif in_peer and line.lower().startswith("publickey"):
                    cur["key"] = line.split("=", 1)[1].strip()
                elif line:
                    pending_comment = None
        if cur.get("key") and cur.get("name"):
            names[cur["key"]] = cur["name"]
    except OSError:
        pass
    return names


def wg_info():
    try:
        out = subprocess.run(["wg", "show", WG_IFACE, "dump"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5).stdout.decode().splitlines()
    except Exception:
        return None
    if not out:
        return None
    iface = out[0].split("\t")
    port = int(iface[2]) if len(iface) > 2 and iface[2].isdigit() else None
    state["wg_port"] = port
    names = wg_names()
    now = time.time()
    peers = []
    for line in out[1:]:
        p = line.split("\t")
        if len(p) < 8:
            continue
        key, endpoint, allowed, hs, rx, tx = p[0], p[2], p[3], int(p[4]), int(p[5]), int(p[6])
        if endpoint != "(none)":
            remember_peer_ip(endpoint.rsplit(":", 1)[0].strip("[]"))
        peers.append({"name": names.get(key) or "", "key": key[:8], "ip": allowed.replace("/32", ""),
                      "endpoint": "" if endpoint == "(none)" else endpoint,
                      "handshake": hs or None, "online": bool(hs and now - hs < 180), "rx": rx, "tx": tx})
    peers.sort(key=lambda x: (not x["online"], -(x["handshake"] or 0)))
    return {"iface": WG_IFACE, "port": port, "peers": peers}


def proxy_info():
    _, est = read_sockets()
    try:
        import pwd
        gost_uid = pwd.getpwnam(PROXY_USER).pw_uid
    except Exception:
        gost_uid = None
    clients = {}
    outbound = 0
    for lip, lport, rip, rport, uid in est:
        if lport in PROXY_PORTS:
            ip = rip[7:] if rip.startswith("::ffff:") else rip
            c = clients.setdefault(ip, {"ip": ip, "conns": 0, "types": set()})
            c["conns"] += 1
            c["types"].add(PROXY_PORTS[lport])
        elif gost_uid is not None and uid == gost_uid:
            outbound += 1
    lst = sorted(clients.values(), key=lambda c: -c["conns"])
    for c in lst:
        c["types"] = sorted(c["types"])
        c["blocked"] = blocked_check(c["ip"])
    return {"clients": lst, "inbound": sum(c["conns"] for c in lst), "outbound": outbound}


def ts_info():
    try:
        out = subprocess.run(["tailscale", "status", "--json"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=8).stdout.decode()
        d = json.loads(out)
    except Exception:
        return None
    peers = []
    for p in (d.get("Peer") or {}).values():
        cur = p.get("CurAddr") or ""
        if cur:
            remember_peer_ip(cur.rsplit(":", 1)[0].strip("[]"))
        peers.append({"name": p.get("HostName", ""), "ip": (p.get("TailscaleIPs") or [""])[0], "os": p.get("OS", ""),
                      "online": bool(p.get("Online")), "via": "trực tiếp" if cur else ("relay " + p.get("Relay", "")
                                                                                      if p.get("Online") else ""),
                      "rx": p.get("RxBytes", 0), "tx": p.get("TxBytes", 0), "last": p.get("LastSeen", "")})
    peers.sort(key=lambda x: (not x["online"], x["name"]))
    self_ = d.get("Self") or {}
    return {"self": self_.get("HostName", ""), "peers": peers}


def _local_ips():
    ips = set()
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=5).stdout.decode()
        for line in out.splitlines():
            p = line.split()
            if len(p) > 3 and p[2] in ("inet", "inet6"):
                ips.add(p[3].split("/")[0])
    except Exception:
        pass
    return ips


# IP của chính VPS: mọi địa chỉ trên card mạng + VPSMON_OWN_IPS (IP public khi VPS nằm sau NAT như Oracle/AWS)
OWN_IPS = _local_ips() | {x.strip() for x in _env("OWN_IPS").split(",") if x.strip()}
NEVER_BLOCK_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "224.0.0.0/3", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "fd7a:115c:a1e0::/48")]
peer_ips = set()


def load_peer_ips():
    try:
        con = db()
        row = con.execute("SELECT v FROM kv WHERE k='peer_ips'").fetchone()
        con.close()
        if row:
            peer_ips.update(json.loads(row[0]))
    except Exception:
        pass


def remember_peer_ip(ip):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return
    if ip in peer_ips:
        return
    peer_ips.add(ip)
    try:
        con = db()
        con.execute("INSERT OR REPLACE INTO kv VALUES('peer_ips', ?)", (json.dumps(sorted(peer_ips)),))
        con.commit()
        con.close()
    except Exception:
        pass


def protect_reason(ip):
    """Lý do không được chặn IP này, hoặc None nếu chặn được."""
    a = ipaddress.ip_address(ip)
    if str(a) in OWN_IPS:
        return "đây là IP của chính VPS"
    if str(a) in peer_ips:
        return "đây là IP mạng của một máy trong Tailscale/WireGuard của bạn (ví dụ mạng nhà)"
    for n in NEVER_BLOCK_NETS:
        if a.version == n.version and a in n:
            return "IP nội bộ/Tailscale/đặc biệt (%s)" % n
    return None


def fw_drop(action, source):
    flag = "--add-source=" if action == "block" else "--remove-source="
    msgs = []
    for extra in ([], ["--permanent"]):           # runtime + permanent, không reload (CentOS 7 reload để lại passthrough cũ)
        r = subprocess.run(["firewall-cmd"] + extra + ["--zone=drop", flag + source],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        out = r.stdout.decode().strip()
        if r.returncode != 0 and "ALREADY_ENABLED" not in out and "NOT_ENABLED" not in out \
                and "UNKNOWN_SOURCE" not in out:
            raise RuntimeError(out or "firewall-cmd lỗi %d" % r.returncode)
        msgs.append(out)
    refresh_blocked()
    print("vpsmon: %s %s -> %s" % (action, source, " | ".join(msgs)), flush=True)


def refresh_public_ports():
    """Cổng đang mở công khai trên zone public của firewalld (gồm cả cổng của service)."""
    try:
        run = lambda *a: subprocess.check_output(["firewall-cmd"] + list(a), stderr=subprocess.DEVNULL,
                                                 timeout=20).decode()
        ports = set(run("--zone=public", "--list-ports").split())
        for svc in run("--zone=public", "--list-services").split():
            for line in run("--info-service=" + svc).splitlines():
                if line.strip().startswith("ports:"):
                    ports.update(line.split(":", 1)[1].split())
        state["public_ports"] = sorted(ports)
    except Exception:
        pass


# ---------------------------------------------------------------- GeoIP (DB-IP Country Lite, CC BY 4.0, https://db-ip.com)
GEO_PATH = os.path.join(DATA_DIR, "country.mmdb")
GEO_URL = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"


class MMDB:
    """Bộ đọc MaxMind DB tối giản (chỉ đọc), dùng mmap nên gần như không tốn RAM."""

    def __init__(self, path):
        import mmap
        self.f = open(path, "rb")
        self.buf = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        i = self.buf.rfind(b"\xab\xcd\xefMaxMind.com")
        if i < 0:
            raise ValueError("không phải file MMDB")
        self.meta, _ = self._decode(i + 14, i + 14)
        self.nodes = self.meta["node_count"]
        self.rsize = self.meta["record_size"]
        self.tree_size = self.rsize * 2 // 8 * self.nodes
        self.data = self.tree_size + 16
        self.v4start = 0
        if self.meta.get("ip_version") == 6:
            node = 0
            for _ in range(96):
                if node >= self.nodes:
                    break
                node = self._read_node(node, 0)
            self.v4start = node

    def close(self):
        self.buf.close()
        self.f.close()

    def _read_node(self, node, bit):
        b = self.buf
        if self.rsize == 24:
            o = node * 6 + bit * 3
            return int.from_bytes(b[o:o + 3], "big")
        if self.rsize == 28:
            o = node * 7
            if bit == 0:
                return ((b[o + 3] & 0xF0) << 20) | int.from_bytes(b[o:o + 3], "big")
            return ((b[o + 3] & 0x0F) << 24) | int.from_bytes(b[o + 4:o + 7], "big")
        o = node * 8 + bit * 4
        return int.from_bytes(b[o:o + 4], "big")

    def _decode(self, off, base):
        b = self.buf
        ctrl = b[off]
        off += 1
        t = ctrl >> 5
        if t == 1:                                     # pointer
            ss, v = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p = (v << 8) | b[off]; off += 1
            elif ss == 1:
                p = ((v << 16) | int.from_bytes(b[off:off + 2], "big")) + 2048; off += 2
            elif ss == 2:
                p = ((v << 24) | int.from_bytes(b[off:off + 3], "big")) + 526336; off += 3
            else:
                p = int.from_bytes(b[off:off + 4], "big"); off += 4
            val, _ = self._decode(base + p, base)
            return val, off
        if t == 0:
            t = 7 + b[off]; off += 1
        size = ctrl & 0x1F
        if size >= 29:
            n = size - 28
            size = (29, 285, 65821)[n - 1] + int.from_bytes(b[off:off + n], "big")
            off += n
        if t == 2:
            return b[off:off + size].decode("utf-8", "replace"), off + size
        if t == 7:
            d = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                d[k] = v
            return d, off
        if t == 11:
            a = []
            for _ in range(size):
                v, off = self._decode(off, base)
                a.append(v)
            return a, off
        if t in (5, 6, 9, 10):
            return int.from_bytes(b[off:off + size], "big"), off + size
        if t == 8:
            return int.from_bytes(b[off:off + size], "big", signed=True), off + size
        if t == 3:
            return struct.unpack(">d", b[off:off + 8])[0], off + 8
        if t == 15:
            return struct.unpack(">f", b[off:off + 4])[0], off + 4
        if t == 14:
            return bool(size), off
        return b[off:off + size], off + size           # bytes / loại khác

    def lookup(self, ip):
        a = ipaddress.ip_address(ip)
        packed = a.packed
        if a.version == 4:
            node, bits = self.v4start, 32
        else:
            node, bits = 0, 128
        for i in range(bits):
            if node >= self.nodes:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == self.nodes:
            return None
        if node > self.nodes:
            off = node - self.nodes - 16 + self.data
            val, _ = self._decode(off, self.data)
            return val
        return None


geo = {"db": None, "cache": {}, "build": ""}
geo_lock = threading.Lock()


def geo_open():
    try:
        db_ = MMDB(GEO_PATH)
        with geo_lock:
            old = geo["db"]
            geo["db"] = db_
            geo["cache"] = {}
            geo["build"] = time.strftime("%Y-%m-%d", time.gmtime(db_.meta.get("build_epoch", 0)))
        if old:
            old.close()
    except Exception as e:
        state["geo"] = "lỗi: %s" % e


def country_of(ip):
    """Trả về mã quốc gia 2 chữ (VN, US…) hoặc '' nếu không biết."""
    c = geo["cache"].get(ip)
    if c is not None:
        return c
    cc = ""
    with geo_lock:
        db_ = geo["db"]
        if db_:
            try:
                r = db_.lookup(ip)
                if isinstance(r, dict):
                    cc = (r.get("country") or {}).get("iso_code") or ""
            except Exception:
                cc = ""
        if len(geo["cache"]) > 20000:
            geo["cache"] = {}
        geo["cache"][ip] = cc
    return cc


def geo_update_loop():
    """Mỗi ngày kiểm tra; nếu file cũ hơn 35 ngày (DB-IP ra bản mới mỗi đầu tháng) thì tải bản tháng hiện tại."""
    import gzip
    import urllib.request
    geo_open()
    while True:
        try:
            age = time.time() - os.path.getmtime(GEO_PATH) if os.path.exists(GEO_PATH) else 1e9
            if age > 35 * 86400:
                for months_back in (0, 1):
                    t = time.gmtime(time.time() - months_back * 28 * 86400)
                    url = GEO_URL % time.strftime("%Y-%m", t)
                    tmp = GEO_PATH + ".tmp"
                    try:
                        with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as out:
                            out.write(gzip.decompress(r.read()))
                        MMDB(tmp).close()                  # kiểm tra file hợp lệ trước khi thay
                        os.replace(tmp, GEO_PATH)
                        geo_open()
                        print("vpsmon: cập nhật GeoIP từ %s" % url, flush=True)
                        break
                    except Exception as e:
                        print("vpsmon: tải GeoIP lỗi %s: %s" % (url, e), flush=True)
                        try:
                            os.remove(tmp)
                        except OSError:
                            pass
        except Exception:
            pass
        time.sleep(86400)


def geo_map(d):
    ips = set()
    for k in ("top_scan", "top_proxy", "recent"):
        ips.update(r["ip"] for r in d.get(k) or [])
    px = (d.get("conns") or {}).get("proxy") or {}
    ips.update(c["ip"] for c in px.get("clients") or [])
    for b in d.get("blocked") or []:
        ips.add(b.split("/")[0])
    out = {}
    for ip in ips:
        try:
            out[ip] = country_of(ip)
        except Exception:
            out[ip] = ""
    return out


# ---------------------------------------------------------------- API
def service_states():
    try:
        out = subprocess.run(["systemctl", "is-active"] + SERVICES, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10).stdout.decode().split()
    except Exception:
        out = []
    res = [{"name": n, "state": out[i] if i < len(out) else "unknown"} for i, n in enumerate(SERVICES)]
    return [r for r in res if r["state"] != "unknown"]          # unknown = unit không tồn tại trên máy này


def cert_info():
    res = []
    for path in glob.glob(CERT_GLOB):
        try:
            c = ssl._ssl._test_decode_cert(path)
            exp = ssl.cert_time_to_seconds(c["notAfter"])
            name = os.path.basename(path)[:-4]
            res.append({"name": name, "days": round((exp - time.time()) / 86400, 1)})
        except Exception:
            continue
    return sorted(res, key=lambda r: r["days"])


def blocked_check(ip):
    try:
        a = ipaddress.ip_address(ip)
        for net in state["blocked"]:
            try:
                if a in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def build_data(rng):
    span = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}.get(rng, 86400)
    bucket = 86400 if span > 7 * 86400 else 3600
    now = time.time()
    since = now - span
    since_h = int(since) // 3600 * 3600
    con = db()
    q = con.execute

    totals = {}
    for kind in ("scan", "proxy", "authfail", "proxyerr"):
        n, ips = q("SELECT COALESCE(SUM(n),0), COUNT(DISTINCT ip) FROM hits WHERE kind=? AND hour>=?",
                   (kind, since_h)).fetchone()
        totals[kind] = n
        totals[kind + "_ips"] = ips
    totals["new_ips"] = q("SELECT COUNT(*) FROM ipseen WHERE first>=?", (since_h,)).fetchone()[0]

    tl = collections.defaultdict(lambda: {"scan": 0, "proxy": 0, "authfail": 0})
    for hour, kind, n in q("SELECT hour, kind, SUM(n) FROM hits WHERE hour>=? AND kind IN ('scan','proxy','authfail') "
                           "GROUP BY hour, kind", (since_h,)):
        b = hour // bucket * bucket
        tl[b][kind] += n
    start = int(since) // bucket * bucket
    timeline = [[b, tl[b]["scan"], tl[b]["proxy"], tl[b]["authfail"]]
                for b in range(start, int(now) + 1, bucket)]

    top_ports = [list(r) for r in q(
        "SELECT proto, port, SUM(n) s, COUNT(DISTINCT ip) FROM hits WHERE kind='scan' AND hour>=? "
        "GROUP BY proto, port ORDER BY s DESC LIMIT 15", (since_h,))]

    top_scan = []
    for ip, n, ports, last in q(
            "SELECT ip, SUM(n) s, COUNT(DISTINCT proto||port), MAX(hour) FROM hits WHERE kind='scan' AND hour>=? "
            "GROUP BY ip ORDER BY s DESC LIMIT 15", (since_h,)):
        top_scan.append({"ip": ip, "n": n, "ports": ports, "last": last, "blocked": blocked_check(ip)})

    top_proxy = []
    for ip, conns, fails, errs, last in q(
            "SELECT ip, SUM(CASE WHEN kind='proxy' THEN n ELSE 0 END) c, "
            "SUM(CASE WHEN kind='authfail' THEN n ELSE 0 END) f, "
            "SUM(CASE WHEN kind='proxyerr' THEN n ELSE 0 END) e, MAX(hour) "
            "FROM hits WHERE kind IN ('proxy','authfail','proxyerr') AND hour>=? "
            "GROUP BY ip ORDER BY f DESC, c DESC LIMIT 15", (since_h,)):
        top_proxy.append({"ip": ip, "conns": conns, "fails": fails, "errs": errs, "last": last,
                          "blocked": blocked_check(ip)})

    recent = [{"ts": r[0], "kind": r[1], "ip": r[2], "proto": r[3], "port": r[4], "msg": r[5]}
              for r in q("SELECT ts, kind, ip, proto, port, msg FROM recent ORDER BY ts DESC LIMIT 60")]

    rows = q("SELECT ts, cpu, mem, swap, rx, tx FROM metrics WHERE ts>=? ORDER BY ts",
             (now - min(span, KEEP_METRICS_DAYS * 86400),)).fetchall()
    step = max(1, len(rows) // 240)
    metrics = [list(r) for r in rows[::step]]
    con.close()

    mt, mu, st, su = read_mem()
    dt, du = read_disk()
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    return {
        "now": now, "range": rng, "bucket": bucket, "host": socket.gethostname(), "uptime": uptime,
        "sys": {"cpu": live.get("cpu"), "mem_total": mt, "mem_used": mu, "swap_total": st, "swap_used": su,
                "disk_total": dt, "disk_used": du, "load": os.getloadavg(), "cpus": os.cpu_count(),
                "rx": live.get("rx"), "tx": live.get("tx"), "proxy_active": proxy_active()},
        "nas": nas if NAS_PATH else None, "wan_if": WAN_IF,
        "services": service_states(), "certs": cert_info(),
        "collectors": {"nflog": state["nflog"], "log proxy": state["proxylog"]},
        "blocked": state["blocked"], "protected": sorted(peer_ips | OWN_IPS), "totals": totals, "timeline": timeline,
        "top_ports": top_ports, "top_scan": top_scan, "top_proxy": top_proxy,
        "recent": recent, "metrics": metrics, "proxy_ports": PROXY_PORTS,
        "conns": {"wg": wg_info(), "proxy": proxy_info(), "ts": ts_info()},
        "svc": services_detail(), "public_ports": state.get("public_ports", []),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            with open(HTML_PATH, "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
        elif u.path == "/api/data":
            rng = parse_qs(u.query).get("range", ["24h"])[0]
            try:
                data = build_data(rng)
                data["geo"] = geo_map(data)
                data["geo_build"] = geo["build"]
                body = json.dumps(data).encode()
                self.send(200, body, "application/json")
            except Exception as e:
                self.send(500, json.dumps({"error": str(e)}).encode(), "application/json")
        else:
            self.send(404, b"not found", "text/plain")


    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/api/block":
            return self.send(404, b"not found", "text/plain")

        def reply(code, **kw):
            self.send(code, json.dumps(kw).encode(), "application/json")
        # Chống CSRF: bắt buộc header riêng + JSON (trình duyệt sẽ chặn trang khác gửi kiểu này),
        # và nếu có Origin thì phải trùng host đang mở dashboard.
        origin = self.headers.get("Origin")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        if self.headers.get("X-Vpsmon") != "1" or "application/json" not in (self.headers.get("Content-Type") or ""):
            return reply(403, ok=False, error="yêu cầu không hợp lệ")
        if origin and urlparse(origin).netloc != host:
            return reply(403, ok=False, error="sai nguồn yêu cầu")
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(min(n, 2048)).decode())
            action = req.get("action")
            raw = str(req.get("ip", "")).strip()
            if action not in ("block", "unblock"):
                return reply(400, ok=False, error="action sai")
            if action == "unblock":
                if raw not in state["blocked"]:
                    return reply(400, ok=False, error="%s không nằm trong danh sách chặn" % raw)
                source = raw
            else:
                ip = ipaddress.ip_address(raw)       # chỉ chặn từng IP; ValueError nếu không phải IP
                why = protect_reason(str(ip))
                if why:
                    return reply(400, ok=False, error="Không chặn %s: %s." % (ip, why))
                if blocked_check(str(ip)):
                    return reply(200, ok=True, msg="%s đã bị chặn từ trước" % ip)
                source = str(ip) + ("/32" if ip.version == 4 else "/128")
            fw_drop(action, source)
            svc_cache["t"] = 0
            return reply(200, ok=True, msg=("Đã chặn " if action == "block" else "Đã bỏ chặn ") + source)
        except ValueError:
            return reply(400, ok=False, error="IP không hợp lệ")
        except Exception as e:
            return reply(500, ok=False, error=str(e)[:300])


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    init_db()
    load_peer_ips()
    refresh_blocked()
    loops = [nflog_loop, metrics_loop, flush_loop]
    if PROXY_UNIT:
        loops.append(gost_loop)
    if NAS_PATH:
        loops.append(nas_loop)
    if GEOIP:
        loops.append(geo_update_loop)
    for fn in loops:
        threading.Thread(target=fn, daemon=True).start()
    Server(LISTEN, Handler).serve_forever()


if __name__ == "__main__":
    main()
