#!/usr/bin/env python3
"""
utr-monitor.py - Poll a UniFi Travel Router (UTR) over SSH and serve a local
dashboard: CPU, memory, per-interface throughput, WAN uplinks and latency,
Teleport/WireGuard VPN status, Wi-Fi networks, radios and clients, nearby
networks, and the router's own event log.
 
Usage:
    pip install paramiko
    python3 utr-monitor.py 192.168.1.1                 # prompts for password
    python3 utr-monitor.py 192.168.1.1 -i 2 --port 8080
    UTR_PASSWORD=secret python3 utr-monitor.py 192.168.1.1
    python3 utr-monitor.py --demo                      # fake data, no device needed
    python3 utr-monitor.py 192.168.1.1 --no-db         # memory only, no SQLite
    python3 utr-monitor.py 192.168.1.1 --once > s.json # one detail poll, dump JSON
 
Then open http://127.0.0.1:8080/
 
How it collects:
  * Tries /proc (stat, meminfo, net/dev, loadavg) first - most accurate.
  * Falls back to BusyBox `top -bn1` + `ifconfig` if /proc reads are blocked.
  * Uses SSH exec channels; if the restricted shell rejects those, it falls
    back to a single interactive shell session with output markers.
  * Every --detail-interval seconds (default 10) it also runs UniFi's own
    tooling: mca-dump, the Teleport status file, multi-WAN ping results,
    DHCP leases and /var/log/utr-runtime-events.log.
  * Reconnects automatically with backoff if the SSH session drops.
"""
 
import argparse
import collections
import getpass
import hashlib
import json
import logging
import math
import os
import random
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
 
log = logging.getLogger("utr")
 
SEP = "@@UTR_SECTION@@"
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]")
 
 
# --------------------------------------------------------------------------- #
# SSH transport
# --------------------------------------------------------------------------- #
class SSHRunner:
    """Runs commands on the device; handles exec vs interactive-shell mode."""
 
    def __init__(self, host, user, password, port=22, timeout=10):
        try:
            import paramiko  # noqa: F401
        except ImportError:
            sys.exit("paramiko is required:  pip install paramiko")
        self.host, self.user, self.password = host, user, password
        self.port, self.timeout = port, timeout
        self.client = None
        self.chan = None
        self.mode = None  # None (unknown) | "exec" | "shell"
        self._n = 0
 
    def connect(self):
        import paramiko
        self.close()
        log.info("Connecting to %s@%s:%d", self.user, self.host, self.port)
        c = paramiko.SSHClient()
        # Travel routers get re-flashed/re-adopted often; accept the host key.
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.host, port=self.port, username=self.user,
                  password=self.password, timeout=self.timeout,
                  banner_timeout=self.timeout, auth_timeout=self.timeout,
                  allow_agent=False, look_for_keys=False)
        c.get_transport().set_keepalive(15)
        self.client = c
 
    def close(self):
        for obj in (self.chan, self.client):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        self.chan = self.client = None
 
    def _alive(self):
        t = self.client and self.client.get_transport()
        return bool(t and t.is_active())
 
    def run(self, cmd):
        if not self._alive():
            self.connect()
        if self.mode in (None, "exec"):
            try:
                out = self._exec(cmd)
                if self.mode == "exec" or out.strip():
                    self.mode = "exec"
                    return out
            except Exception as e:
                if self.mode == "exec":
                    raise
                log.info("exec channel unusable (%s); trying interactive shell", e)
            self.mode = "shell"
            log.info("Using interactive shell mode")
        return self._shell(cmd)
 
    def _exec(self, cmd):
        _, stdout, _ = self.client.exec_command(cmd, timeout=self.timeout)
        return stdout.read().decode("utf-8", "replace")
 
    def _shell_read_until(self, needle, deadline):
        buf = ""
        while time.time() < deadline:
            if self.chan.recv_ready():
                buf += self.chan.recv(65536).decode("utf-8", "replace")
                if needle is None or needle in buf:
                    if needle is None:
                        time.sleep(0.2)
                        continue
                    return buf
            elif self.chan.closed or self.chan.exit_status_ready():
                raise ConnectionError("shell channel closed")
            else:
                time.sleep(0.05)
        if needle is None:
            return buf
        raise TimeoutError("timed out waiting for shell output")
 
    def _shell(self, cmd):
        if self.chan is None or self.chan.closed:
            self.chan = self.client.invoke_shell(term="dumb", width=4000, height=2000)
            self._shell_read_until(None, time.time() + 1.5)  # drain banner/prompt
        self._n += 1
        marker = f"__UTR_DONE_{self._n}__"
        # Quoting splits the marker in the echoed command line, so only the
        # real echo output contains the contiguous marker string.
        self.chan.send(f'{cmd}; echo "__UTR_""DONE_{self._n}__"\n')
        raw = self._shell_read_until(marker, time.time() + self.timeout)
        text = ANSI_RE.sub("", raw).replace("\r", "")
        body = text.split(marker)[0]
        lines = body.split("\n")
        # Drop everything up to and including the echoed command line.
        for i, ln in enumerate(lines):
            if '"__UTR_""DONE_' in ln:
                lines = lines[i + 1:]
                break
        return "\n".join(lines)
 
 
# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
PROC_CMD = (f"cat /proc/stat; echo {SEP}; cat /proc/meminfo; echo {SEP}; "
            f"cat /proc/net/dev; echo {SEP}; cat /proc/loadavg; echo {SEP}; uptime")
TOP_CMD = (f"top -bn1 | head -n 6; echo {SEP}; "
           f"cat /proc/net/dev 2>/dev/null || ifconfig 2>/dev/null; echo {SEP}; uptime")
 
 
def parse_proc_stat(text):
    for ln in text.splitlines():
        if ln.startswith("cpu "):
            f = [int(x) for x in ln.split()[1:]]
            f += [0] * (8 - len(f))
            total = sum(f[:8])
            idle = f[3] + f[4]
            return total, idle
    return None
 
 
def parse_meminfo(text):
    m = {}
    for ln in text.splitlines():
        mm = re.match(r"(\w+):\s+(\d+)", ln)
        if mm:
            m[mm.group(1)] = int(mm.group(2))  # kB
    if "MemTotal" not in m:
        return None
    total = m["MemTotal"]
    if "MemAvailable" in m:
        used = total - m["MemAvailable"]
    else:
        used = total - m.get("MemFree", 0) - m.get("Buffers", 0) - m.get("Cached", 0)
    return total, used
 
 
def parse_net(text):
    """Return {iface: (rx_bytes, tx_bytes)} from /proc/net/dev or ifconfig."""
    out = {}
    if "Inter-" in text or "|bytes" in text:
        for ln in text.splitlines():
            if ":" not in ln or "|" in ln:
                continue
            name, data = ln.split(":", 1)
            f = data.split()
            if len(f) >= 9:
                out[name.strip()] = (int(f[0]), int(f[8]))
        return out
    name = None
    for ln in text.splitlines():
        if ln and not ln[0].isspace():
            name = ln.split()[0].rstrip(":")
        if not name:
            continue
        rx = re.search(r"RX (?:packets \d+\s+)?bytes[: ](\d+)", ln)
        tx = re.search(r"TX (?:packets \d+\s+)?bytes[: ](\d+)", ln)
        cur = list(out.get(name, (None, None)))
        if rx:
            cur[0] = int(rx.group(1))
        if tx:
            cur[1] = int(tx.group(1))
        if rx or tx:
            out[name] = tuple(cur)
    return {k: v for k, v in out.items() if None not in v}
 
 
def parse_top(text):
    res = {}
    m = re.search(r"Mem:\s*(\d+)K used,\s*(\d+)K free", text)
    if m:
        used, free = int(m.group(1)), int(m.group(2))
        buff = re.search(r"(\d+)K buff", text)
        cached = re.search(r"(\d+)K cached", text)
        real_used = used - (int(buff.group(1)) if buff else 0) - (int(cached.group(1)) if cached else 0)
        res["mem"] = (used + free, max(real_used, 0))
    m = re.search(r"CPU:.*?([\d.]+)%\s*idle", text)
    if m:
        res["cpu"] = max(0.0, 100.0 - float(m.group(1)))
    m = re.search(r"Load average:\s*([\d.]+)", text, re.I)
    if m:
        res["load1"] = float(m.group(1))
    return res
 


# --------------------------------------------------------------------------- #
# Detail poll: UniFi's own status tooling (mca-dump, Teleport, multi-WAN, events)
# --------------------------------------------------------------------------- #
DETAIL_CMD = "; ".join([
    "mca-dump 2>/dev/null", "echo @S@",
    "cat /tmp/teleport-client.d/connection-status.json 2>/dev/null", "echo @S@",
    "wg show all latest-handshakes 2>/dev/null", "echo @S@",
    "wg show all transfer 2>/dev/null", "echo @S@",
    'for f in /var/run/unifi_mwan.status.ping.*; do [ -f "$f" ] && echo "${f##*.} $(cat "$f")"; done', "echo @S@",
    "cat /tmp/leases.* 2>/dev/null", "echo @S@",
    "cat /proc/net/arp", "echo @S@",
    "tail -n 300 /var/log/utr-runtime-events.log 2>/dev/null", "echo @S@",
    "ip route show default", "echo @S@",
    "ip -4 -o addr", "echo @S@",
    "cat /proc/net/wireless", "echo @S@",
    "cat /proc/uptime /proc/sys/kernel/random/boot_id /etc/version 2>/dev/null", "echo @S@",
    "brctl showmacs br-lan 2>/dev/null", "echo @S@",
    'for p in /sys/class/net/br-lan/brif/*; do echo "${p##*/} $(cat "$p/port_no")"; done 2>/dev/null',
]).replace("@S@", SEP)

# Per-process CPU accounting, appended to the detail poll after its own marker.
# `echo $$` is the poll's shell; its parent is the dropbear session serving this monitor.
PROC_SEP = "@@UTR_PROCS@@"
DETAIL_CMD += (f"; echo {PROC_SEP}; echo $$; cat /proc/uptime; grep '^cpu' /proc/stat; echo {SEP}; "
               f"cat /proc/net/dev; echo {SEP}; cat /proc/[0-9]*/stat 2>/dev/null; echo {SEP}; ps w 2>/dev/null")

BAND = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}
TELEPORT_DAEMONS = ("teleport-client", "wireguard-client", "openvpn-client")
SHELLS = ("sh", "ash", "bash", "busybox")


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _sat(x):
    """UniFi 'satisfaction' (experience) score; -1 means not applicable."""
    x = _num(x)
    return None if x is None or x < 0 else x


def _json(text, default=None):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def parse_procs(stat_t, ps_t):
    """Parse concatenated /proc/<pid>/stat lines (+ `ps w` for command lines)."""
    cmds = {}
    for ln in ps_t.splitlines()[1:]:
        f = ln.split(None, 4)
        if len(f) >= 5 and f[0].isdigit():
            cmds[int(f[0])] = f[4]
    procs = {}
    for ln in stat_t.splitlines():
        lp, rp = ln.find("("), ln.rfind(")")
        if lp < 0 or rp < lp:
            continue
        try:
            pid = int(ln[:lp])
            f = ln[rp + 2:].split()
            procs[pid] = {"pid": pid, "comm": ln[lp + 1:rp], "ppid": int(f[1]),
                          "own": int(f[11]) + int(f[12]), "child": int(f[13]) + int(f[14]),
                          "start": int(f[19]), "cmd": cmds.get(pid, "")}
        except (ValueError, IndexError):
            continue
    return procs


def _proc_label(p):
    if p["ppid"] == 2 or p["pid"] == 2:
        return f"[{p['comm']}]"
    if p["comm"] in SHELLS and p["cmd"]:
        return p["cmd"][:48]
    return p["comm"]


def parse_detail(text, now):
    """Turn the DETAIL_CMD output into (state, series, events)."""
    p = [x.strip() for x in text.split(SEP)]
    p += [""] * (14 - len(p))
    (mca_t, tele_t, hs_t, xfer_t, ping_t, lease_t, arp_t, ev_t,
     route_t, addr_t, wl_t, misc_t, fdb_t, brif_t) = p[:14]
    mca = _json(mca_t, {}) or {}
    if not isinstance(mca, dict):
        mca = {}
    tele = _json(tele_t)
    tele = tele if isinstance(tele, dict) else None

    misc = misc_t.splitlines()
    uptime = _num(misc[0].split()[0]) if misc and misc[0].split() else _num(mca.get("uptime"))
    boot_id = misc[1].strip() if len(misc) > 1 else ""
    firmware = mca.get("version") or (misc[2].strip() if len(misc) > 2 else "")
    boot_epoch = now - uptime if uptime else None
    router_now = _num(mca.get("time")) or now

    addrs = {}
    for ln in addr_t.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)/", ln)
        if m and not m.group(2).startswith("169.254."):  # link-local means no real lease
            addrs.setdefault(m.group(1), m.group(2))

    routes = []
    for ln in route_t.splitlines():
        m, mm = re.search(r"\bdev (\S+)", ln), re.search(r"\bmetric (\d+)", ln)
        if m:
            routes.append((int(mm.group(1)) if mm else 0, m.group(1)))
    active = mca.get("uplink") or (min(routes)[1] if routes else None)

    latency, targets = {}, {}
    for ln in ping_t.splitlines():
        name, _, js = ln.partition(" ")
        data = _json(js, {})
        rows = data.get("latency", []) if isinstance(data, dict) else []
        vals = {r.get("target"): _num(r.get("latency_ms")) for r in rows if isinstance(r, dict)}
        good = [v for v in vals.values() if v is not None]
        if good:
            latency[name] = round(sum(good) / len(good), 1)
            targets[name] = vals

    leases = {}
    for ln in lease_t.splitlines():
        f = ln.split()
        if len(f) >= 4:
            leases[f[1].lower()] = {"ip": f[2], "host": "" if f[3] == "*" else f[3]}

    wireless = {}
    for ln in wl_t.splitlines():
        m = re.match(r"\s*([\w.-]+):\s+\w+\s+[-\d.]+\s+([-\d.]+)", ln)
        if m and _num(m.group(2)):
            wireless[m.group(1)] = _num(m.group(2))

    # Wi-Fi networks (VAPs) and radios
    vaps = []
    for v in mca.get("vap_table") or []:
        vaps.append({
            "name": v.get("name"), "essid": v.get("essid") or "", "radio": v.get("radio"),
            "band": BAND.get(v.get("radio"), v.get("radio") or ""), "channel": v.get("channel"),
            "bw": v.get("bw"), "num_sta": v.get("num_sta") or 0, "tx_power": v.get("tx_power"),
            "satisfaction": _sat(v.get("satisfaction")), "usage": v.get("usage") or "",
            "up": v.get("up"), "bssid": (v.get("bssid") or "").lower(),
            "_sta": v.get("sta_table") or []})
    radios, neighbours = [], []
    for r in mca.get("radio_table") or []:
        st = r.get("athstats") or {}
        mine = [v for v in vaps if v["radio"] == r.get("radio")]
        ap = next((v for v in mine if v["usage"] == "user"), mine[0] if mine else {})
        radios.append({
            "name": r.get("name"), "band": BAND.get(r.get("radio"), r.get("radio") or ""),
            "channel": ap.get("channel"), "bw": ap.get("bw"),
            "cu_total": st.get("cu_total"), "cu_self_tx": st.get("cu_self_tx"),
            "cu_self_rx": st.get("cu_self_rx"), "noise": st.get("noise_floor"),
            "satisfaction": _sat(st.get("satisfaction")), "max_txpower": r.get("max_txpower"),
            "nss": r.get("nss")})
        for s in r.get("scan_table") or []:
            neighbours.append({
                "essid": s.get("essid") or "", "bssid": (s.get("bssid") or "").lower(),
                "band": BAND.get(s.get("band"), s.get("band") or ""), "channel": s.get("channel"),
                "bw": s.get("bw"), "signal": s.get("signal"), "security": s.get("security") or "",
                "model": s.get("model_display") if s.get("is_unifi") else ""})

    # Clients: Wi-Fi from the AP station tables, wired from the LAN bridge ARP table
    clients, seen = [], set()
    for v in vaps:
        if v["usage"] != "user":
            continue
        for s in v["_sta"]:
            mac = (s.get("mac") or "").lower()
            seen.add(mac)
            lease = leases.get(mac, {})
            std = ("Wi-Fi 6" if s.get("is_11ax") else "Wi-Fi 5" if s.get("is_11ac")
                   else "Wi-Fi 4" if s.get("is_11n") else "legacy")
            clients.append({
                "mac": mac, "name": s.get("hostname") or lease.get("host") or "",
                "ip": s.get("ip") or lease.get("ip") or "", "conn": f"{v['essid']} · {v['band']}",
                "iface": v["name"], "wired": False, "signal": s.get("signal"),
                "rx_rate": s.get("rx_rate"), "tx_rate": s.get("tx_rate"), "mcs": s.get("tx_mcs"),
                "uptime": s.get("uptime"), "idle": s.get("idletime"),
                "rx_bytes": s.get("rx_bytes"), "tx_bytes": s.get("tx_bytes"),
                "satisfaction": _sat(s.get("satisfaction")), "std": std})
    # Bridge forwarding table: which bridge port each MAC was last seen on, and how long ago.
    # ARP entries linger after a Wi-Fi client leaves, so this is what decides "wired".
    ports, fdb = {}, {}
    for ln in brif_t.splitlines():
        f = ln.split()
        if len(f) == 2:
            try:
                ports[int(f[1], 0)] = f[0]
            except ValueError:
                pass
    for ln in fdb_t.splitlines():
        f = ln.split()
        if len(f) >= 4 and f[0].isdigit() and f[2] == "no":
            fdb[f[1].lower()] = (ports.get(int(f[0]), ""), _num(f[3]))
    lan_speed = {l.get("interface"): l.get("speed") for l in mca.get("lan_table") or [] if l.get("interface")}
    lan_port = next((i for i in lan_speed if i.startswith("eth")), None)
    for ln in arp_t.splitlines()[1:]:
        f = ln.split()
        if len(f) >= 6 and f[5].startswith("br-") and f[2] == "0x2" and f[3].lower() not in seen:
            mac = f[3].lower()
            port = None
            if fdb:
                port, age = fdb.get(mac, (None, None))
                if not port or port.startswith("ath") or age is None or age > 300:
                    continue  # a Wi-Fi client that has left, or not heard from recently
            seen.add(mac)
            iface = port or lan_port or f[5]
            speed = lan_speed.get(iface)
            clients.append({
                "mac": mac, "name": leases.get(mac, {}).get("host", ""), "ip": f[0],
                "conn": "Wired · LAN port" if iface.startswith("eth") else f"Wired · {iface}",
                "iface": iface, "wired": True,
                "tx_rate": speed * 1000 if speed else None, "rx_rate": speed * 1000 if speed else None})

    # WAN uplinks
    portal = {}
    cands = []
    for pd in mca.get("portal_detect") or []:
        if pd.get("wan_if"):
            cands.append(pd["wan_if"])
            portal[pd["wan_if"]] = pd.get("state")
    bridges = {v["name"]: v for v in vaps if v["usage"] == "wireless-bridge"}
    if not cands:
        cands = sorted({i for _, i in routes} | set(bridges))
    lldp = {}
    for l in mca.get("lldp_table") or []:
        bits = [l.get("chassis_descr") or l.get("chassis_id"), l.get("port_descr") or l.get("port_id")]
        lldp[l.get("local_port_name")] = " · ".join(b for b in bits if b)
    wans = []
    for i in cands:
        signal = None
        if i in bridges:
            v = bridges[i]
            kind = " ".join(x for x in ("Wi-Fi", v["essid"] or "uplink", v["band"]) if x)
            if v["essid"] and addrs.get(i):  # only an associated uplink has a meaningful signal
                signal = wireless.get(i)
                if signal is None or signal <= -95:
                    signal = next((n["signal"] for n in neighbours if n["bssid"] == v["bssid"]), None)
        elif i.startswith("usb"):
            kind = "USB tether"
        elif i.startswith("eth"):
            kind = "Ethernet"
        elif i.startswith("ath"):
            kind = f"Wi-Fi ({i})"
        else:
            kind = i
        wans.append({
            "iface": i, "kind": kind, "label": "WAN · " + kind, "active": i == active,
            "connected": bool(addrs.get(i)), "ip": addrs.get(i), "portal": portal.get(i),
            "latency": latency.get(i), "targets": targets.get(i), "signal": signal,
            "neighbour": lldp.get(i)})
    wans.sort(key=lambda w: (not w["active"], not w["connected"], w["iface"]))

    # VPN
    hs, xfer = {}, {}
    for ln in hs_t.splitlines():
        f = ln.split()
        if len(f) >= 3 and f[2].isdigit():
            hs[f[0]] = max(hs.get(f[0], 0), int(f[2]))
    for ln in xfer_t.splitlines():
        f = ln.split()
        if len(f) >= 4 and f[2].isdigit() and f[3].isdigit():
            rx, tx = xfer.get(f[0], (0, 0))
            xfer[f[0]] = (rx + int(f[2]), tx + int(f[3]))
    wg = {}
    for i in set(hs) | set(xfer):
        ts = hs.get(i) or 0
        wg[i] = {"handshake_age": round(router_now - ts) if ts else None,
                 "rx_bytes": xfer.get(i, (None, None))[0], "tx_bytes": xfer.get(i, (None, None))[1]}
    teleport = None
    if tele:
        keep = ("state", "detailed_status", "message", "site_name", "uptime_seconds", "client_ip",
                "endpoint", "rx_bytes", "tx_bytes", "killswitch_enabled", "internet_state", "profile_id")
        teleport = {k: tele.get(k) for k in keep}
    teleport_on = bool(teleport and teleport.get("state") not in (None, "", "missing", "DISCONNECTED"))

    # Friendly interface names for the throughput picker
    ifaces = {}
    for w in wans:
        ifaces[w["iface"]] = {"label": w["label"] + (" (active)" if w["active"] else ""),
                              "role": "wan", "order": 0 if w["active"] else 2}
    for i in wg:
        ifaces[i] = {"label": "VPN · Teleport" if teleport else "VPN · WireGuard", "role": "vpn", "order": 1}
    ifaces["br-lan"] = {"label": "LAN · all clients", "role": "lan", "order": 3}
    for v in vaps:
        if v["usage"] == "user":
            ifaces[v["name"]] = {"label": f"Wi-Fi · {v['essid']} {v['band']}", "role": "wifi", "order": 4}
    for l in mca.get("lan_table") or []:
        i = l.get("interface")
        if i and i not in ifaces:
            ifaces[i] = {"label": "LAN port" if i.startswith("eth") else f"LAN · {i}", "role": "lan", "order": 5}

    ss = mca.get("system-stats") or {}
    system = {
        "hostname": mca.get("hostname"), "model": mca.get("model_display"), "firmware": firmware,
        "uptime": uptime, "internet": mca.get("internet"), "satisfaction": _sat(mca.get("satisfaction")),
        "cpu": _num(ss.get("cpu")), "mem": _num(ss.get("mem")), "lan_ip": mca.get("lan_ip"),
        "gateway": mca.get("gateway_ip"), "active_wan": active, "mca": bool(mca)}

    events = []
    for ln in ev_t.splitlines():
        ln = ln.strip()
        e = _json(ln) if ln.startswith("{") else None
        if not isinstance(e, dict):
            continue
        mono, ts = _num(e.get("monotonic")), _num(e.get("ts"))
        t = boot_epoch + mono if (boot_epoch is not None and mono is not None) else ts
        if t is None:
            continue
        events.append({
            "id": hashlib.sha1((boot_id + ln).encode()).hexdigest()[:20], "t": round(t, 1),
            "category": e.get("category") or "", "event": e.get("event") or "",
            "details": e.get("details") if isinstance(e.get("details"), dict) else {}})

    for v in vaps:
        v.pop("_sta", None)
    uplink_signal = next((w["signal"] for w in wans if w["signal"] is not None and w["connected"]), None)
    series = {
        "lat": {w["iface"]: w["latency"] for w in wans if w["connected"]},
        "cu": {r["band"]: r["cu_total"] for r in radios if r["cu_total"] is not None},
        "ncl": sum(1 for c in clients if not c["wired"]),
        "usig": uplink_signal,
        "vpn": 1 if (teleport_on or any((w["handshake_age"] or 1e9) < 180 for w in wg.values())) else 0}
    state = {"t": round(now, 3), "system": system, "wans": wans, "vpn": {"teleport": teleport, "wg": wg},
             "vaps": vaps, "radios": radios, "clients": clients,
             "neighbours": sorted(neighbours, key=lambda n: -(n["signal"] or -999)), "ifaces": ifaces}
    return state, series, events


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
class Store:
    """SQLite persistence for fast samples, detail series and router events."""

    COLS = ("t", "cpu", "mem_pct", "mem_used_mb", "mem_total_mb", "load1")

    def __init__(self, path, retention_days=0):
        self.path = path
        self.retention = float(retention_days or 0) * 86400
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS samples (
            t REAL PRIMARY KEY, cpu REAL, mem_pct REAL, mem_used_mb REAL,
            mem_total_mb REAL, load1 REAL, net TEXT NOT NULL DEFAULT '{}')""")
        self.db.execute("CREATE TABLE IF NOT EXISTS details (t REAL PRIMARY KEY, data TEXT NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, t REAL, category TEXT, event TEXT, details TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS events_t ON events(t)")
        self.db.commit()
        self.count = self.db.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        self._last_prune = 0.0
        self._prune()

    def _prune(self):
        if not self.retention:
            return
        cut = time.time() - self.retention
        cur = self.db.execute("DELETE FROM samples WHERE t < ?", (cut,))
        self.count -= max(cur.rowcount, 0)
        self.db.execute("DELETE FROM details WHERE t < ?", (cut,))
        self.db.execute("DELETE FROM events WHERE t < ?", (cut,))
        self.db.commit()
        self._last_prune = time.time()

    def _row(self, r):
        d = dict(zip(self.COLS, r[:6]))
        d["net"] = json.loads(r[6] or "{}")
        return d

    def add(self, s):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?)",
                            [s[c] for c in self.COLS] + [json.dumps(s["net"], separators=(",", ":"))])
            self.db.commit()
            self.count += 1
            if self.retention and time.time() - self._last_prune > 600:
                self._prune()

    def add_detail(self, d):
        with self.lock:
            data = {k: v for k, v in d.items() if k != "t"}
            self.db.execute("INSERT OR REPLACE INTO details VALUES (?,?)",
                            (d["t"], json.dumps(data, separators=(",", ":"))))
            self.db.commit()

    def add_events(self, events):
        if not events:
            return
        with self.lock:
            self.db.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)",
                                [(e["id"], e["t"], e["category"], e["event"],
                                  json.dumps(e["details"], separators=(",", ":"))) for e in events])
            self.db.commit()

    def recent(self, limit):
        with self.lock:
            rows = self.db.execute("SELECT * FROM (SELECT * FROM samples ORDER BY t DESC LIMIT ?) "
                                   "ORDER BY t", (limit,)).fetchall()
        return [self._row(r) for r in rows]

    def recent_details(self, limit):
        with self.lock:
            rows = self.db.execute("SELECT * FROM (SELECT * FROM details ORDER BY t DESC LIMIT ?) "
                                   "ORDER BY t", (limit,)).fetchall()
        return [dict(json.loads(r[1]), t=r[0]) for r in rows]

    def recent_events(self, limit):
        with self.lock:
            rows = self.db.execute("SELECT * FROM (SELECT * FROM events ORDER BY t DESC LIMIT ?) "
                                   "ORDER BY t", (limit,)).fetchall()
        return [{"id": r[0], "t": r[1], "category": r[2], "event": r[3], "details": json.loads(r[4] or "{}")}
                for r in rows]

    def iter_all(self):
        conn = sqlite3.connect(self.path)  # separate reader; WAL lets it run alongside writes
        try:
            for r in conn.execute("SELECT * FROM samples ORDER BY t"):
                yield self._row(r)
        finally:
            conn.close()

    def reset(self):
        with self.lock:
            for table in ("samples", "details", "events"):
                self.db.execute(f"DELETE FROM {table}")
            self.db.commit()
            self.db.execute("VACUUM")
            self.count = 0

    def close(self):
        with self.lock:
            self.db.close()


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #
EVENT_MEMORY = 1000


class Collector(threading.Thread):
    def __init__(self, runner, interval, history, iface_filter=None, store=None, detail_interval=10.0):
        super().__init__(daemon=True)
        self.runner, self.interval = runner, interval
        self.detail_interval = detail_interval
        self.samples = collections.deque(maxlen=history)
        self.details = collections.deque(maxlen=history)
        self.events = collections.deque(maxlen=EVENT_MEMORY)
        self.iface_filter = set(iface_filter or [])
        self.lock = threading.Lock()
        self.status = {"connected": False, "error": None, "method": None,
                       "uptime": "", "host": getattr(runner, "host", "demo"),
                       "db": store.path if store else None, "db_rows": 0, "reset_gen": 0,
                       "detail_ms": None, "detail_error": None}
        self.store = store
        self.state = None
        self.eseq = 0
        self.seen = set()
        self.prev_clients = {}
        self.prev_procsnap = None
        self.prev_port_net = None
        self.counted = {}       # (pid, start) -> ticks already attributed (or pre-window)
        self.tpoll = set()      # (pid, start) of processes seen spawning Teleport status commands
        self.last_detail = 0.0
        if store:
            self.samples.extend(store.recent(history))
            self.details.extend(store.recent_details(history))
            for e in store.recent_events(EVENT_MEMORY):
                self.eseq += 1
                e["seq"] = self.eseq
                self.events.append(e)
                self.seen.add(e["id"])
            log.info("Loaded %d samples, %d detail points, %d events from %s",
                     len(self.samples), len(self.details), len(self.events), store.path)
        self.method = None
        self.prev_cpu = None
        self.prev_net = None
        self.prev_t = None
        self.warm = False

    def _keep_iface(self, name):
        if self.iface_filter:
            return name in self.iface_filter
        return name != "lo"

    def _detect(self):
        out = self.runner.run(PROC_CMD)
        if "cpu " in out and "MemTotal" in out:
            self.method = "proc"
        else:
            log.info("/proc not readable, falling back to top/ifconfig")
            self.method = "top"
        self.status["method"] = self.method
        log.info("Collection method: %s (ssh mode: %s)", self.method,
                 getattr(self.runner, "mode", "n/a"))

    def poll_once(self):
        if self.method is None:
            self._detect()
        now = time.time()
        sample = {"t": round(now, 3), "cpu": None, "mem_pct": None,
                  "mem_used_mb": None, "mem_total_mb": None, "load1": None, "net": {}}

        if self.method == "proc":
            parts = self.runner.run(PROC_CMD).split(SEP)
            parts += [""] * (5 - len(parts))
            stat, mem_t, net_t, load_t, up_t = parts[:5]
            cpu = parse_proc_stat(stat)
            if cpu and self.prev_cpu:
                dt_total = cpu[0] - self.prev_cpu[0]
                dt_idle = cpu[1] - self.prev_cpu[1]
                if dt_total > 0:
                    sample["cpu"] = round(100.0 * (1 - dt_idle / dt_total), 2)
            self.prev_cpu = cpu
            mem = parse_meminfo(mem_t)
            lm = re.match(r"\s*([\d.]+)", load_t)
            if lm:
                sample["load1"] = float(lm.group(1))
        else:
            parts = self.runner.run(TOP_CMD).split(SEP)
            parts += [""] * (3 - len(parts))
            top_t, net_t, up_t = parts[:3]
            t = parse_top(top_t)
            sample["cpu"] = t.get("cpu")
            sample["load1"] = t.get("load1")
            mem = t.get("mem")

        if mem:
            total, used = mem
            sample["mem_total_mb"] = round(total / 1024, 1)
            sample["mem_used_mb"] = round(used / 1024, 1)
            sample["mem_pct"] = round(100.0 * used / total, 2) if total else None

        net = {k: v for k, v in parse_net(net_t).items() if self._keep_iface(k)}
        if self.prev_net and self.prev_t:
            dt = now - self.prev_t
            for name, (rx, tx) in net.items():
                if name in self.prev_net and dt > 0:
                    prx, ptx = self.prev_net[name]
                    drx, dtx = rx - prx, tx - ptx
                    if drx >= 0 and dtx >= 0:  # skip counter wrap/reset
                        sample["net"][name] = [round(drx / dt, 1), round(dtx / dt, 1)]
        self.prev_net, self.prev_t = net, now
        self.status["uptime"] = up_t.strip().splitlines()[-1] if up_t.strip() else ""
        return sample

    def _cpu_accounting(self, now, text, active_wan):
        """Attribute CPU time between two detail polls to process groups.

        Live processes contribute their own utime+stime deltas. Time of children
        that exited is credited to the parent (cutime/cstime), minus whatever was
        already counted for those children while they were visible, so nothing is
        counted twice. Percentages are of the whole machine (all cores).
        """
        parts = text.split(SEP)
        parts += [""] * (4 - len(parts))
        hdr = [ln for ln in parts[0].splitlines() if ln.strip()]
        try:
            shell_pid = int(hdr[0])
            uptime = float(hdr[1].split()[0])
            cpus = [ln for ln in hdr[2:] if ln.startswith("cpu")]
            tot = [int(x) for x in cpus[0].split()[1:]][:8]
        except (IndexError, ValueError):
            return {}
        tot += [0] * (8 - len(tot))
        ncpu = max(1, len(cpus) - 1)
        net = parse_net(parts[1])
        procs = parse_procs(parts[2], parts[3])
        prev, self.prev_procsnap = self.prev_procsnap, {"t": now, "tot": tot, "uptime": uptime,
                                                         "procs": procs, "net": net}
        keys = {pid: (pid, p["start"]) for pid, p in procs.items()}

        def baseline():
            self.counted = {k: (procs[pid]["own"] + procs[pid]["child"], procs[pid]["ppid"]) for pid, k in keys.items()}
        if not prev:
            baseline()
            return {}
        dtot = [a - b for a, b in zip(tot, prev["tot"])]
        total, dt = sum(dtot), now - prev["t"]
        if total <= 0 or dt <= 0:
            baseline()
            return {}
        hz = total / ncpu / dt
        mon = procs.get(shell_pid, {}).get("ppid")

        # Remember who spawns Teleport status commands (e.g. the LCD or BLE daemon).
        for pid, p in procs.items():
            if p["comm"] in TELEPORT_DAEMONS:
                continue
            if "teleport" in p["cmd"] or "teleport" in p["comm"]:
                q = p
                for _ in range(8):
                    par = procs.get(q["ppid"])
                    if not par or par["pid"] in (1, mon):
                        break
                    if "teleport" not in par["cmd"]:
                        self.tpoll.add(keys[par["pid"]])
                        break
                    q = par

        def group(pid):
            p = procs[pid]
            if p["comm"] in TELEPORT_DAEMONS or p["comm"].startswith("wg-crypt") or \
                    (p["comm"] == "dnsmasq" and "teleport" in p["cmd"]):
                return "teleport"
            if p["ppid"] == 2 or pid == 2:
                return "kernel"
            q = p
            for _ in range(10):
                if q["pid"] == mon:
                    return "monitor"
                if "teleport" in q["cmd"]:
                    return "teleport_poll"
                q = procs.get(q["ppid"])
                if not q:
                    break
            return "other"

        # Children that vanished since the last poll were reaped by their parent.
        reaped = collections.defaultdict(int)
        live = set(keys.values())
        for key, (ticks, ppid) in self.counted.items():
            if key not in live:
                reaped[ppid] += ticks
        counted, groups, items = {}, collections.defaultdict(int), []
        for pid, p in procs.items():
            key = keys[pid]
            q = prev["procs"].get(pid)
            if q and q["start"] == p["start"] and key in self.counted:
                d_own = max(0, p["own"] - q["own"])
                d_child = max(0, p["child"] - q["child"] - reaped.get(pid, 0))
                done = self.counted[key][0] + d_own + d_child
            elif p["start"] / hz >= prev["uptime"] - 1:   # started during this interval
                d_own, d_child, done = p["own"], 0, p["own"]  # its reaped children surface via its parent later
            else:
                counted[key] = (p["own"] + p["child"], p["ppid"])
                continue
            counted[key] = (done, p["ppid"])
            g = group(pid)
            if d_own:
                groups[g] += d_own
                items.append((_proc_label(p), g, d_own))
            if d_child:
                gc = "teleport_poll" if key in self.tpoll and g == "other" else g
                groups[gc] += d_child
                items.append((_proc_label(p) + " (children)", gc, d_child))
        self.counted = counted
        self.tpoll &= live

        pc = lambda ticks: round(100.0 * ticks / total, 2)
        busy = total - dtot[3] - dtot[4]
        groups["unattributed"] = max(0, busy - sum(groups.values()))
        merged = collections.defaultdict(lambda: [None, 0])
        for label, g, ticks in items:
            merged[label][0] = g
            merged[label][1] += ticks
        top = sorted(merged.items(), key=lambda kv: -kv[1][1])[:12]

        def rate(names):
            b = 0
            for n in names:
                if n in net and n in prev["net"]:
                    b += max(0, sum(net[n]) - sum(prev["net"][n]))
            return round(b / dt, 1)
        vpn_bps = rate([n for n in net if n.startswith(("wg", "tun"))])
        wan_bps = rate([active_wan]) if active_wan else None
        return {"cpu_all": pc(busy), "cpu_us": pc(dtot[0] + dtot[1]), "cpu_sy": pc(dtot[2]),
                "cpu_si": pc(dtot[5] + dtot[6]), "cpu_io": pc(dtot[4]),
                "grp": {g: pc(v) for g, v in groups.items()},
                "top": [[label, g, pc(t)] for label, (g, t) in top if t],
                "vpn_bps": vpn_bps, "wan_bps": wan_bps,
                "nonvpn_bps": None if wan_bps is None else max(0.0, wan_bps - vpn_bps)}

    def poll_detail(self):
        t0 = time.time()
        raw = self.runner.run(DETAIL_CMD)
        now = time.time()
        out, _, proc_t = raw.partition(PROC_SEP)
        state, series, events = parse_detail(out, now)
        try:
            series.update(self._cpu_accounting(now, proc_t, state["system"]["active_wan"]))
        except Exception as e:  # never let accounting break the rest of the detail poll
            log.warning("CPU accounting failed: %s", e)
        # Wired clients: the router has no per-device counters, only per port. A port's
        # tx is its clients' download. With several devices on one port the figures are shared.
        pparts = proc_t.split(SEP)
        port_net = parse_net(pparts[1]) if len(pparts) > 1 else {}
        wired = collections.defaultdict(list)
        for c in state["clients"]:
            if c["wired"] and c["iface"] in port_net:
                wired[c["iface"]].append(c)
        for port, cs in wired.items():
            rx, tx = port_net[port]
            for c in cs:
                c["tx_bytes"], c["rx_bytes"] = tx, rx
                c["mac_key"] = port  # rate is tracked per port, not per device
                if len(cs) > 1:
                    c["shared"] = len(cs)
        # Per-client throughput from byte-counter deltas. The AP's tx is the client's download.
        current = {}
        for c in state["clients"]:
            if c.get("tx_bytes") is None:
                continue
            key = c.pop("mac_key", c["mac"])
            prev = self.prev_clients.get(key)
            if prev and now > prev[0]:
                d_down, d_up = c["tx_bytes"] - prev[1], c["rx_bytes"] - prev[2]
                if d_down >= 0 and d_up >= 0:
                    c["down_bps"] = round(d_down / (now - prev[0]), 1)
                    c["up_bps"] = round(d_up / (now - prev[0]), 1)
            current[key] = (now, c["tx_bytes"], c["rx_bytes"])
        self.prev_clients = current
        detail = dict(series, t=round(now, 3))
        new = sorted((e for e in events if e["id"] not in self.seen), key=lambda e: e["t"])
        with self.lock:
            self.state = state
            self.details.append(detail)
            for e in new:
                self.seen.add(e["id"])
                self.eseq += 1
                e["seq"] = self.eseq
                self.events.append(e)
            if len(self.seen) > 20000:
                self.seen = {e["id"] for e in events} | {e["id"] for e in self.events}
            self.status.update(detail_ms=round((now - t0) * 1000), detail_error=None)
        if self.store:
            self.store.add_detail(detail)
            self.store.add_events(new)
        return state

    def run(self):
        backoff = 2
        while True:
            start = time.time()
            try:
                s = self.poll_once()
                with self.lock:
                    if self.warm:  # first poll only primes the delta counters
                        self.samples.append(s)
                        if self.store:
                            try:
                                self.store.add(s)
                            except Exception as e:
                                log.warning("DB write failed: %s", e)
                    self.warm = True
                    self.status.update(connected=True, error=None)
                backoff = 2
            except Exception as e:
                log.warning("Poll failed: %s", e)
                with self.lock:
                    self.status.update(connected=False, error=str(e))
                try:
                    self.runner.close()
                except Exception:
                    pass
                self.method = None
                self.warm = False
                self.prev_cpu = self.prev_net = self.prev_t = None
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            if self.detail_interval and time.time() - self.last_detail >= self.detail_interval:
                self.last_detail = time.time()
                try:
                    self.poll_detail()
                except Exception as e:
                    log.warning("Detail poll failed: %s", e)
                    with self.lock:
                        self.status["detail_error"] = str(e)
            time.sleep(max(0.0, self.interval - (time.time() - start)))

    def reset(self):
        with self.lock:
            self.samples.clear()
            self.details.clear()
            self.events.clear()  # `seen` is kept so old log lines don't reappear
            if self.store:
                self.store.reset()
            self.status["reset_gen"] += 1
        log.info("History reset from web UI")

    def snapshot(self, since=0.0, dsince=0.0, eseq=0):
        with self.lock:
            st = dict(self.status)
            st["db_rows"] = self.store.count if self.store else 0
            return {"status": st, "interval": self.interval, "dinterval": self.detail_interval,
                    "history": self.samples.maxlen,
                    "samples": [s for s in self.samples if s["t"] > since],
                    "details": [d for d in self.details if d["t"] > dsince],
                    "events": [e for e in self.events if e["seq"] > eseq],
                    "state": self.state}


class DemoRunner:
    """Fakes the router's output so the UI can be tried without a device."""
    host = "demo"
    mode = "demo"

    def __init__(self):
        self.t0 = time.time()
        self.cpu = [0, 0]
        self.net = {k: [0, 0] for k in ("lo", "eth0", "eth1", "ath1", "ath5", "br-lan", "wg0", "wifi1")}
        self.cbytes = {}
        self.vpn_cycles = 0
        self.dlast = None
        self.dcpu = [0] * 8
        self.shell = 5000
        self.procs = {  # pid: [comm, ppid, own, child, start, cmd]
            1: ["procd", 0, 300, 900, 1, "/sbin/procd"], 2: ["kthreadd", 0, 0, 0, 1, ""],
            7: ["ksoftirqd/0", 2, 500, 0, 2, ""], 40: ["kworker/u8:1", 2, 800, 0, 3, ""],
            41: ["kworker/0:2", 2, 300, 0, 3, ""], 1498: ["wg-crypt-wg0", 2, 0, 0, 900, ""],
            1566: ["dnsmasq", 1, 40, 0, 900, "/usr/sbin/dnsmasq -k -C /tmp/teleport-client.d/dnsmasq.teleport.conf"],
            2455: ["teleport-client", 1, 1200, 50, 950, "/usr/bin/teleport-client"],
            2456: ["wireguard-client", 1, 300, 0, 950, "/usr/bin/wireguard-client"],
            2457: ["openvpn-client", 1, 120, 0, 950, "/usr/bin/openvpn-client"],
            3629: ["lcm-display", 1, 600, 4000, 1000, "/usr/bin/lcm-display"],
            2458: ["mcad", 1, 900, 200, 950, "/usr/bin/mcad"],
            12477: ["wevent", 1, 100, 0, 1200, "/sbin/wevent"],
            900: ["dropbear", 1, 50, 0, 2000, "/usr/sbin/dropbear -F -r /var/run/dropbear_rsa_host_key"]}
        self.ev = []
        for mono, cat, ev, det in [
                (40, "collector", "started", {"interval": "10"}),
                (56, "uplink_dhcp", "dhcp_bound", {"iface": "eth0", "ip": "192.168.1.50", "router": "192.168.1.1"}),
                (57, "internet", "internet_on", {"iface": "eth0", "portal_state": "open", "new": "on:eth0:open:route"}),
                (73, "wifi_uplink", "wifi_connected", {"iface": "ath5", "ssid": "Hotel-Guest", "freq": "5180"}),
                (104, "vpn", "vpn_on", {"new": "openvpn=missing;teleport=CONNECTED;wireguard=missing"})]:
            self._event(mono, cat, ev, det)

    def _event(self, mono, cat, ev, det):
        self.ev.append(json.dumps({"ts": int(time.time()), "monotonic": mono, "category": cat,
                                   "event": ev, "details": det}))

    def close(self):
        pass

    def run(self, cmd):
        if cmd == DETAIL_CMD:
            return self._detail()
        el = time.time() - self.t0
        busy = int(30 + 25 * math.sin(el / 20) + random.uniform(0, 20))
        self.cpu[0] += busy
        self.cpu[1] += 100 - busy
        avail = int(260000 + 20000 * math.sin(el / 45))
        mem = f"MemTotal: 512000 kB\nMemFree: 100000 kB\nMemAvailable: {avail} kB"
        rate = max(0, 4e6 + 3e6 * math.sin(el / 15) + random.uniform(-1e6, 1e6))
        share = {"eth0": (1, .2), "br-lan": (.2, 1), "eth1": (.05, .3), "ath1": (.15, .7),
                 "wg0": (.6, .15), "ath5": (.001, .001), "lo": (.01, .01), "wifi1": (.15, .7)}
        for k, (a, b) in share.items():
            self.net[k][0] += int(rate * a)
            self.net[k][1] += int(rate * b)
        nd = "Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n"
        nd += "".join(f"  {k}: {v[0]} 0 0 0 0 0 0 0 {v[1]} 0 0 0 0 0 0 0\n" for k, v in self.net.items())
        return (f"cpu  {self.cpu[0]} 0 0 {self.cpu[1]} 0 0 0 0\n{SEP}\n{mem}\n{SEP}\n{nd}{SEP}\n"
                f"{busy / 50:.2f} 0.5 0.4 1/80 999\n{SEP}\n up {int(el)}s, load average: 0.5")

    def _detail(self):
        r = random.uniform
        el = time.time() - self.t0
        up = int(el) + 3600
        cycle = int(el // 300)  # a Teleport reconnect every 5 minutes
        while self.vpn_cycles < cycle:
            self.vpn_cycles += 1
            m = 3600 + self.vpn_cycles * 300
            self._event(m, "vpn", "vpn_off", {"new": "openvpn=missing;teleport=CONNECTING;wireguard=missing"})
            self._event(m + 20, "vpn", "vpn_on", {"new": "openvpn=missing;teleport=CONNECTED;wireguard=missing"})
        people = [("aa:11:22:33:44:01", "Laptop", "192.168.29.20", -48, 866000, 99),
                  ("aa:11:22:33:44:02", "Phone", "192.168.29.21", -61, 400000, 92),
                  ("aa:11:22:33:44:03", "", "192.168.29.22", -72, 72000, 74)]
        sta = []
        for i, (mac, host, ip, sig, rate, sat) in enumerate(people):
            b = self.cbytes.setdefault(mac, [0, 0])
            b[0] += int(r(1e4, 4e5) / (i + 1))
            b[1] += int(r(1e5, 3e6) / (i + 1))
            sta.append({"mac": mac, "hostname": host, "ip": ip, "signal": sig + int(r(-3, 3)),
                        "rx_rate": rate, "tx_rate": int(rate * .9), "tx_mcs": 9 - 2 * i,
                        "uptime": up - 900 * i, "idletime": int(r(0, 5)), "rx_bytes": b[0], "tx_bytes": b[1],
                        "satisfaction": sat, "is_11ac": i < 2, "is_11n": True})
        mca = {
            "hostname": "Demo-UTR", "model_display": "UniFi Travel Router", "version": "6.6.122",
            "uptime": up, "time": int(time.time()), "internet": True, "uplink": "eth0", "satisfaction": 93,
            "lan_ip": "192.168.29.1", "gateway_ip": "192.168.1.1",
            "system-stats": {"cpu": f"{r(15, 60):.1f}", "mem": "52.0"},
            "portal_detect": [{"wan_if": "eth0", "state": "open", "default_route": True},
                              {"wan_if": "ath5", "state": "open", "default_route": False},
                              {"wan_if": "usb0", "state": "unknown", "default_route": False}],
            "lldp_table": [{"local_port_name": "eth0", "chassis_descr": "Example Switch", "port_descr": "Port 7"}],
            "lan_table": [{"interface": "eth1", "speed": 1000}, {"interface": "ath0"}, {"interface": "ath1"}],
            "vap_table": [
                {"name": "ath0", "essid": "TravelNet", "radio": "ng", "channel": 6, "bw": 20, "num_sta": 0,
                 "tx_power": 11, "satisfaction": -1, "usage": "user", "up": True, "sta_table": []},
                {"name": "ath1", "essid": "TravelNet", "radio": "na", "channel": 36, "bw": 80, "num_sta": 3,
                 "tx_power": 11, "satisfaction": 94, "usage": "user", "up": True, "sta_table": sta},
                {"name": "ath5", "essid": "Hotel-Guest", "radio": "na", "channel": 36, "bw": 80, "num_sta": 0,
                 "tx_power": 11, "satisfaction": -1, "usage": "wireless-bridge", "up": True,
                 "bssid": "02:00:00:00:00:01", "sta_table": []}],
            "radio_table": [
                {"name": "wifi0", "radio": "ng", "max_txpower": 13, "nss": 2,
                 "athstats": {"cu_total": int(r(10, 35)), "cu_self_tx": 1, "cu_self_rx": 0,
                              "noise_floor": -95, "satisfaction": -1},
                 "scan_table": [{"essid": "Cafe-WiFi", "bssid": "02:00:00:00:01:01", "band": "ng", "channel": 1,
                                 "bw": 20, "signal": -71, "security": "WPA2-Personal", "is_unifi": False}]},
                {"name": "wifi1", "radio": "na", "max_txpower": 15, "nss": 2,
                 "athstats": {"cu_total": int(r(5, 25)), "cu_self_tx": 3, "cu_self_rx": 1,
                              "noise_floor": -96, "satisfaction": 94},
                 "scan_table": [
                     {"essid": "Hotel-Guest", "bssid": "02:00:00:00:00:01", "band": "na", "channel": 36,
                      "bw": 80, "signal": -58, "security": "Open", "is_unifi": True, "model_display": "U6-LR"},
                     {"essid": "", "bssid": "02:00:00:00:01:02", "band": "na", "channel": 44, "bw": 80,
                      "signal": -82, "security": "WPA3-Personal", "is_unifi": False}]}]}
        tele = {"state": "CONNECTED", "detailed_status": "CONNECTED", "message": "Teleport connection active",
                "site_name": "Home-Gateway", "uptime_seconds": int(el % 300), "client_ip": "192.168.2.25",
                "endpoint": "203.0.113.10:41458", "rx_bytes": self.net["wg0"][0], "tx_bytes": self.net["wg0"][1],
                "killswitch_enabled": False, "internet_state": "open", "profile_id": "1"}
        now = int(time.time())
        ping = lambda base: json.dumps({"latency": [{"target": t, "latency_ms": int(base + r(0, base))}
                                                    for t in ("1.1.1.1", "8.8.8.8", "www.microsoft.com")]})
        sections = [
            json.dumps(mca), json.dumps(tele),
            f"wg0\tPEER=\t{now - int(r(1, 30))}", f"wg0\tPEER=\t{self.net['wg0'][0]}\t{self.net['wg0'][1]}",
            f"eth0 {ping(6)}\nath5 {ping(18)}",
            "1792590000 aa:11:22:33:44:03 192.168.29.22 Tablet *",
            "IP address HW type Flags HW address Mask Device\n"
            "192.168.29.50 0x1 0x2 aa:11:22:33:44:09 * br-lan\n192.168.1.1 0x1 0x2 02:00:00:00:00:fe * eth0",
            "\n".join(self.ev[-300:]),
            "default via 192.168.1.1 dev eth0 metric 100\ndefault via 192.168.1.1 dev ath5 metric 200",
            "2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n"
            "9: ath5    inet 192.168.1.51/24 brd 192.168.1.255 scope global ath5\n"
            "10: br-lan    inet 192.168.29.1/24 brd 192.168.29.255 scope global br-lan",
            f"Inter-| sta-|\n face | tus |\n  ath5: 0005   44.  {-58 + int(r(-3, 3))}.  -96.   0 0 0 0 0 0",
            f"{up}.00 1000.00\ndemo-boot\n6.6.122",
            "port no\tmac addr\t\tis local?\tageing timer\n  1\taa:11:22:33:44:09\tno\t\t   0.20\n"
            "  2\taa:11:22:33:44:01\tno\t\t   0.10",
            "eth1 0x1\nath1 0x2"]
        return f"\n{SEP}\n".join(sections) + "\n" + PROC_SEP + "\n" + self._procs(up)

    def _procs(self, up):
        r = random.uniform
        now = time.time()
        dt = now - self.dlast if self.dlast else 10.0
        self.dlast = now
        vpn = getattr(self, "_vpn_prev", None)
        wg = self.net["wg0"][0] + self.net["wg0"][1]
        mbps = (wg - vpn) * 8 / 1e6 / dt if vpn is not None else 0
        self._vpn_prev = wg
        hz, ncpu = 100, 4
        total = int(hz * ncpu * dt)
        P = self.procs
        add = lambda pid, own=0.0, child=0.0: (P[pid].__setitem__(2, P[pid][2] + int(own * hz * dt)),
                                               P[pid].__setitem__(3, P[pid][3] + int(child * hz * dt)))
        crypto = 0.006 * mbps               # cores busy per Mb/s of VPN traffic
        add(40, own=crypto * .7)
        add(7, own=crypto * .2)
        add(2455, own=.02 + r(0, .01))
        add(2456, own=.004)
        add(1566, own=.001)
        add(3629, own=.01, child=.05 + r(0, .02))   # LCD polling utr-api get-teleport-status
        add(2458, own=.01, child=.005)
        add(900, child=.09 + r(0, .02))            # this monitor's previous detail poll (mca-dump)
        sys_t = int((crypto * .1 + .04) * hz * dt)
        si_t = int(crypto * .9 * hz * dt)
        user_t = int((.25 + r(0, .1)) * hz * dt)
        idle = max(0, total - sys_t - si_t - user_t)
        for i, v in ((0, user_t), (2, sys_t), (3, idle), (6, si_t)):
            self.dcpu[i] += v
        self.shell += 7
        shell_start = int((up - 1) * hz)
        lines = [f"{pid} ({c}) S {pp} 0 0 0 0 0 0 0 0 0 {own} 0 {ch} 0 20 0 1 0 {st} 0 0"
                 for pid, (c, pp, own, ch, st, _) in P.items()]
        lines.append(f"{self.shell} (sh) S 900 0 0 0 0 0 0 0 0 0 2 0 0 0 20 0 1 0 {shell_start} 0 0")
        lines.append(f"{self.shell + 1} (sh) S 3629 0 0 0 0 0 0 0 0 0 1 0 0 0 20 0 1 0 {shell_start} 0 0")
        ps = "  PID USER       VSZ STAT COMMAND\n" + "".join(
            f"{pid} ui 1000 S {cmd or '[' + c + ']'}\n" for pid, (c, pp, own, ch, st, cmd) in P.items())
        ps += f"{self.shell + 1} ui 2532 S sh -c syswrapper.sh utr-api get-teleport-status\n"
        nd = "Inter-|\n face |\n" + "".join(f"  {k}: {v[0]} 0 0 0 0 0 0 0 {v[1]} 0 0 0 0 0 0 0\n"
                                            for k, v in self.net.items())
        cpu = "cpu  " + " ".join(map(str, self.dcpu)) + "\n" + "".join(f"cpu{i} 0 0 0 0 0 0 0 0\n" for i in range(ncpu))
        return (f"{self.shell}\n{up}.00 1000.00\n{cpu}{SEP}\n{nd}{SEP}\n" + "\n".join(lines) + f"\n{SEP}\n{ps}")


# --------------------------------------------------------------------------- #
# Saved password (system keychain via the optional `keyring` package)
# --------------------------------------------------------------------------- #
KEYRING_SERVICE = "utr-monitor"


def _keyring():
    try:
        import keyring
        keyring.get_keyring()
        return keyring
    except Exception:
        return None


def stored_password(user, host):
    kr = _keyring()
    if not kr:
        return None
    try:
        return kr.get_password(KEYRING_SERVICE, f"{user}@{host}")
    except Exception as e:
        log.debug("keyring read failed: %s", e)
        return None


def save_password(user, host, password):
    kr = _keyring()
    if not kr:
        return False
    try:
        kr.set_password(KEYRING_SERVICE, f"{user}@{host}", password)
        return True
    except Exception as e:
        log.warning("Couldn't save the password to the keychain: %s", e)
        return False


def forget_password(user, host):
    kr = _keyring()
    if not kr:
        return False
    try:
        kr.delete_password(KEYRING_SERVICE, f"{user}@{host}")
        return True
    except Exception:
        return False


def resolve_password(user, host, password=None):
    """Return (password, source): --password, $UTR_PASSWORD, the keychain, or a prompt."""
    if password:
        return password, "argument"
    if os.environ.get("UTR_PASSWORD"):
        return os.environ["UTR_PASSWORD"], "environment"
    saved = stored_password(user, host)
    if saved:
        return saved, "keychain"
    return getpass.getpass(f"Password for {user}@{host}: "), "prompt"


def login(runner, source, save=True):
    """Check the password before starting. A rejected saved password is removed and
    you're asked again; a password you typed is saved once it works. If the router
    can't be reached yet, carry on and let the collector keep retrying."""
    import paramiko
    for attempt in range(3):
        try:
            runner.connect()
            break
        except paramiko.AuthenticationException:
            if source == "keychain":
                log.warning("The saved password for %s@%s was rejected; removing it", runner.user, runner.host)
                forget_password(runner.user, runner.host)
            elif source != "prompt":
                sys.exit(f"SSH login to {runner.user}@{runner.host} failed: password rejected")
            if attempt == 2:
                sys.exit(f"SSH login to {runner.user}@{runner.host} failed after 3 attempts")
            runner.password = getpass.getpass(f"Password rejected. Password for {runner.user}@{runner.host}: ")
            source = "prompt"
        except Exception as e:
            log.warning("Can't reach %s yet (%s); will keep retrying", runner.host, e)
            return
    if source == "prompt" and save:
        if save_password(runner.user, runner.host, runner.password):
            log.info("Password saved to the system keychain (remove it with --forget-password)")
        else:
            log.info("To remember the password between runs: pip install keyring")


# --------------------------------------------------------------------------- #
# Web UI
# --------------------------------------------------------------------------- #
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UTR Monitor</title>
<script>try{document.documentElement.dataset.skin=localStorage.getItem('utr.skin')||'classic'}catch(e){document.documentElement.dataset.skin='classic'}</script>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#6b7280;--grid:#e5e7eb;--chip:#eef1f5;
 --c1:#2563eb;--c2:#d97706;--c3:#059669;--c4:#7c3aed;--c5:#db2777;--bad:#dc2626;--ok:#16a34a;--warn:#d97706}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#181c24;--fg:#e6e8ee;--chip:#232834;
 --muted:#9097a3;--grid:#2a303b;--c1:#60a5fa;--c2:#fbbf24;--c3:#34d399;--c4:#a78bfa;--c5:#f472b6;
 --bad:#f87171;--ok:#4ade80;--warn:#fbbf24}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;padding:14px 16px}
h1{font-size:17px;margin:0;font-weight:600}.muted{color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted);margin-right:6px;vertical-align:middle}
.spacer{flex:1}select,button{background:var(--card);color:var(--fg);border:1px solid var(--grid);
 border-radius:6px;padding:4px 8px;font:inherit}
button{cursor:pointer;padding:4px 10px}button:hover{border-color:var(--bad);color:var(--bad)}
.tiles{display:grid;gap:14px;padding:0 16px 14px;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr))}
.tile .v{font-size:18px;font-weight:600;margin-top:2px}.tile .s{color:var(--muted);font-size:12.5px;margin-top:2px}
.k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
main{display:grid;gap:14px;padding:0 16px 14px;grid-template-columns:repeat(auto-fit,minmax(min(420px,100%),1fr))}
.wide{display:grid;gap:14px;padding:0 16px 16px}
.sec{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin:6px 16px 10px;
 padding-bottom:6px;border-bottom:1px solid var(--grid)}
main.netc{grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr))}
/* ---- "UniFi style" theme: same layout, dark network-console look (always dark) ---- */
:root[data-skin=unifi]{color-scheme:dark;--bg:#121315;--card:#1b1d20;--fg:#e8e9eb;--muted:#8b919a;--grid:#2a2d31;
 --chip:#25282c;--head:#202327;--accent:#4797ff;--c1:#4797ff;--c2:#fdb022;--c3:#32d583;--c4:#9b8afb;--c5:#f670c7;
 --bad:#f97066;--ok:#32d583;--warn:#fdb022}
:root[data-skin=unifi] body{font-size:13px}
:root[data-skin=unifi] header{background:var(--card);border-bottom:1px solid var(--grid);padding:10px 20px;margin-bottom:18px;
 position:sticky;top:0;z-index:5}
:root[data-skin=unifi] h1{font-size:15px;display:flex;align-items:center;gap:8px}
:root[data-skin=unifi] h1::before{content:"";width:18px;height:18px;border-radius:5px;background:var(--accent);
 box-shadow:inset 0 0 0 5px color-mix(in srgb,var(--accent) 70%,#fff)}
:root[data-skin=unifi] .tiles,:root[data-skin=unifi] main,:root[data-skin=unifi] .wide{padding-left:20px;padding-right:20px;gap:16px}
:root[data-skin=unifi] .card{border-radius:8px;padding:14px 16px;box-shadow:0 1px 2px rgba(0,0,0,.25)}
:root[data-skin=unifi] .card h2{font-size:14px;margin-bottom:10px}
:root[data-skin=unifi] .sec{text-transform:none;letter-spacing:0;font-size:17px;color:var(--fg);border:0;margin:14px 20px 10px;padding:0}
:root[data-skin=unifi] .k{text-transform:none;letter-spacing:0;font-size:12.5px;font-weight:500}
:root[data-skin=unifi] .tile{border-top:3px solid var(--accent);padding-top:12px}
:root[data-skin=unifi] .tile .v{font-size:20px;margin-top:4px}
:root[data-skin=unifi] th{background:var(--head);font-size:12px;font-weight:600;padding:8px 10px}
:root[data-skin=unifi] td{padding:8px 10px}
:root[data-skin=unifi] tbody tr:hover td{background:var(--head)}
:root[data-skin=unifi] .chip{border-radius:4px;font-weight:500;padding:1px 8px}
:root[data-skin=unifi] select,:root[data-skin=unifi] button{border-radius:6px;padding:5px 10px}
:root[data-skin=unifi] button.tgl{color:var(--accent);background:transparent;border-color:transparent;font-weight:500}
:root[data-skin=unifi] button.tgl:hover{background:var(--head);border-color:var(--grid)}
:root[data-skin=unifi] tr.sel td{color:var(--accent)}
@media (max-width:480px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--grid);border-radius:10px;padding:12px 14px;min-width:0}
.card h2{font-size:13px;margin:0 0 6px;font-weight:600;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-variant-numeric:tabular-nums;min-height:20px}
.legend i{display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:5px;vertical-align:middle}
canvas{width:100%;height:190px;display:block;cursor:crosshair}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
td,th{text-align:left;padding:5px 8px;border-bottom:1px solid var(--grid);white-space:nowrap}
th{color:var(--muted);font-weight:500;font-size:12.5px}td.n,th.n{text-align:right}
tr.sel td{color:var(--c1);font-weight:600}tbody.pick tr{cursor:pointer}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.faint{opacity:.55}
.chip{display:inline-block;padding:1px 7px;border-radius:9px;background:var(--chip);font-size:12px;color:var(--muted)}
.two{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(380px,100%),1fr))}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--muted)}dd{margin:0}
.evs{max-height:360px;overflow-y:auto}
.empty{color:var(--muted);padding:6px 0}
h3{font-size:12.5px;margin:0 0 4px;font-weight:600}
button.tgl{margin-left:auto;font-size:12px;font-weight:400;padding:2px 9px}button.tgl:hover{border-color:var(--c1);color:var(--c1)}
.cpu-more{display:none}.cpu-card.open{grid-column:1/-1}
.cpu-card.open .cpu-grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(360px,100%),1fr))}
.cpu-card.open .cpu-more{display:block}
</style></head><body>
<header>
 <h1>UTR Monitor</h1><span id="host" class="muted"></span>
 <span><span id="dot" class="dot"></span><span id="st" class="muted">connecting…</span></span>
 <span id="up" class="muted"></span><span id="db" class="muted"></span><span class="spacer"></span>
 <label class="muted">Window <select id="win">
  <option value="300">5 min</option><option value="900" selected>15 min</option>
  <option value="3600">1 hour</option><option value="21600">6 hours</option><option value="0">All</option></select></label>
 <label class="muted">Theme <select id="skin"><option value="classic">Classic</option><option value="unifi">UniFi style</option></select></label>
 <button id="reset" title="Delete all collected history">Reset data</button>
</header>
<section class="tiles">
 <div class="card tile"><div class="k">Internet</div><div id="t-net"></div></div>
 <div class="card tile"><div class="k">VPN</div><div id="t-vpn"></div></div>
 <div class="card tile"><div class="k">Wi-Fi</div><div id="t-wifi"></div></div>
 <div class="card tile"><div class="k">Router</div><div id="t-sys"></div></div>
</section>
<h2 class="sec">System</h2>
<main class="sys">
 <div class="card cpu-card" id="cpucard"><h2>CPU <button id="cpumore" class="tgl" aria-expanded="false" aria-controls="cpucard">Show breakdown ▸</button></h2>
  <div class="cpu-grid">
   <div><div class="legend" id="lg-cpu"></div><canvas id="cpu"></canvas></div>
   <div class="cpu-more"><h3>By type <span class="muted" style="font-weight:400">· per detail poll</span></h3><div class="legend" id="lg-cpubk"></div><canvas id="cpubk"></canvas></div>
   <div class="cpu-more"><h3>By group <span class="muted" style="font-weight:400">· per detail poll</span></h3><div class="legend" id="lg-cpugrp"></div><canvas id="cpugrp"></canvas></div>
  </div></div>
 <div class="card"><h2>Memory</h2><div class="legend" id="lg-mem"></div><canvas id="mem"></canvas></div>
  <div class="card"><h2>Teleport CPU cost <span class="chip">estimate</span></h2><canvas id="tcost" style="height:220px"></canvas><div id="tcost-txt" style="margin-top:8px"></div></div>
</main>
<section class="wide">
 <div class="card"><h2>Top processes</h2><div class="tw" id="procs"></div></div>
</section>
<h2 class="sec">Network</h2>
<main class="netc">
 <div class="card"><h2>Throughput <select id="iface"></select></h2><div class="legend" id="lg-net"></div><canvas id="net"></canvas></div>
 <div class="card"><h2>WAN latency</h2><div class="legend" id="lg-lat"></div><canvas id="lat"></canvas></div>
 <div class="card"><h2>Channel utilisation</h2><div class="legend" id="lg-cu"></div><canvas id="cu"></canvas></div>
 <div class="card"><h2>Wi-Fi uplink signal</h2><div class="legend" id="lg-usig"></div><canvas id="usig"></canvas></div>
</main>
<section class="wide">
 <div class="card"><h2>Uplinks</h2><div class="tw" id="wans"></div></div>
 <div class="card"><h2>Clients <span id="ncl" class="chip"></span></h2><div class="tw" id="clients"></div></div>
 <div class="two">
  <div class="card"><h2>VPN</h2><div id="vpn"></div></div>
  <div class="card"><h2>Interfaces</h2><div class="tw" id="ifs"></div></div>
 </div>
 <div class="two">
  <div class="card"><h2>Wi-Fi networks</h2><div class="tw" id="vaps"></div></div>
  <div class="card"><h2>Radios</h2><div class="tw" id="radios"></div></div>
 </div>
 <div class="card"><h2>Nearby networks</h2><div class="tw" id="nbrs"></div></div>
 <div class="card"><h2>Events
  <select id="evcat"><option value="">All categories</option></select>
  <label class="muted"><input type="checkbox" id="evdhcp"> DHCP retries</label>
  <span class="muted" style="font-weight:400">· markers on charts:
   <span style="color:var(--c3)">▼</span> internet <span style="color:var(--c4)">▼</span> VPN
   <span style="color:var(--c2)">▼</span> Wi-Fi uplink <span style="color:var(--c5)">▼</span> USB</span></h2>
  <div class="evs tw" id="events"></div></div>
</section>
<script>
const S={samples:[],details:[],events:[],state:null,last:0,dlast:0,eseq:0,gen:null,db:null,
 interval:2,dinterval:10,history:3600,hoverT:null,iface:null};
const $=id=>document.getElementById(id);
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const PAL=['--c1','--c2','--c3','--c4','--c5'];
const HIDE=/^(lo|sit\d*|ifb\d+|soc\d+|miireg|wifi\d+)$/;
function fmtBits(Bps){if(Bps==null)return'–';let b=Bps*8,u=['b/s','kb/s','Mb/s','Gb/s'],i=0;
 while(b>=1000&&i<u.length-1){b/=1000;i++}return b.toFixed(b<10&&i?2:b<100&&i?1:0)+' '+u[i]}
function fmtBytes(b){if(b==null)return'–';const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}
 return b.toFixed(i?1:0)+' '+u[i]}
const fmtLink=k=>k?(k>=1000?Math.round(k/1000)+' Mb/s':k+' kb/s'):'–';
function fmtDur(s){if(s==null)return'–';s=Math.round(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
 return d?`${d}d ${h}h`:h?`${h}h ${m}m`:m?`${m}m ${s%60}s`:`${s}s`}
const pct=v=>v==null?'–':(+v).toFixed(1)+'%';
const tstr=t=>new Date(t*1000).toLocaleTimeString([],{hour12:false});
const dtstr=t=>new Date(t*1000).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
const cap=s=>s?String(s).charAt(0)+String(s).slice(1).toLowerCase():'';
const sig=v=>v==null?'–':`<span class="${v>=-60?'ok':v>=-70?'warn':'bad'}">${esc(v)} dBm</span>`;
const exp=v=>v==null?'–':`<span class="${v>=80?'ok':v>=50?'warn':'bad'}">${esc(Math.round(v))}%</span>`;
function niceMax(v){if(v<=0)return 1;const p=Math.pow(10,Math.floor(Math.log10(v)));
 for(const m of[1,2,2.5,5,10])if(m*p>=v)return m*p;return 10*p}
function nearest(ts,t){let lo=0,hi=ts.length-1;while(hi-lo>1){const m=(lo+hi)>>1;if(ts[m]<t)lo=m;else hi=m}
 return Math.abs(ts[lo]-t)<=Math.abs(ts[hi]-t)?lo:hi}

function draw(id,times,series,opt){
 const c=$(id),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,W=c.clientWidth,H=c.clientHeight;
 c.width=W*dpr;c.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);ctx.font='11px system-ui,sans-serif';
 const P={l:62,r:10,t:8,b:20},pw=W-P.l-P.r,ph=H-P.t-P.b;c._geo=null;
 if(times.length<2){ctx.fillStyle=css('--muted');ctx.textBaseline='middle';ctx.fillText(opt.empty||'Waiting for data…',P.l,P.t+ph/2);return null}
 const t0=times[0],t1=times[times.length-1];
 const mn=opt.min??0;let mx=opt.max;
 if(mx==null){let m=-Infinity;for(const s of series)for(const v of s.values)if(v!=null&&v>m)m=v;mx=m>mn?mn+niceMax((m-mn)*1.1):mn+1}
 const X=t=>P.l+(t-t0)/(t1-t0||1)*pw,Y=v=>P.t+ph-((Math.max(mn,Math.min(mx,v))-mn)/(mx-mn))*ph;
 ctx.strokeStyle=css('--grid');ctx.fillStyle=css('--muted');ctx.lineWidth=1;ctx.textAlign='right';ctx.textBaseline='middle';
 for(let i=0;i<=4;i++){const v=mn+(mx-mn)*i/4,y=Math.round(Y(v))+.5;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(W-P.r,y);ctx.stroke();ctx.fillText(opt.fmt(v),P.l-6,y)}
 ctx.textAlign='center';ctx.textBaseline='top';
 const n=Math.max(2,Math.floor(pw/90));for(let i=0;i<=n;i++){const t=t0+(t1-t0)*i/n;ctx.fillText(tstr(t),Math.min(Math.max(X(t),P.l+22),W-P.r-22),P.t+ph+5)}
 for(const m of opt.markers||[]){if(m.t<t0||m.t>t1)continue;const x=Math.round(X(m.t))+.5,col=css(m.color);
  ctx.strokeStyle=col;ctx.globalAlpha=.45;ctx.beginPath();ctx.moveTo(x,P.t);ctx.lineTo(x,P.t+ph);ctx.stroke();ctx.globalAlpha=1;
  ctx.fillStyle=col;ctx.beginPath();ctx.moveTo(x-4,P.t);ctx.lineTo(x+4,P.t);ctx.lineTo(x,P.t+6);ctx.fill()}
 const gap=opt.gap||1e9;
 series.forEach((s,si)=>{const col=css(s.color),segs=[];let cur=null;
  times.forEach((t,i)=>{const v=s.values[i];if(v==null||(i&&t-times[i-1]>gap))cur=null;if(v==null)return;
   if(!cur)segs.push(cur=[]);cur.push([X(t),Y(v)])});
  for(const g of segs){ctx.beginPath();g.forEach(([x,y],k)=>k?ctx.lineTo(x,y):ctx.moveTo(x,y));
   if(g.length===1){ctx.fillStyle=col;ctx.fillRect(g[0][0]-1,g[0][1]-1,2,2)}
   ctx.strokeStyle=col;ctx.lineWidth=1.6;ctx.stroke();
   if(si===0&&opt.fill&&g.length>1){ctx.lineTo(g[g.length-1][0],P.t+ph);ctx.lineTo(g[0][0],P.t+ph);ctx.closePath();
    ctx.globalAlpha=.12;ctx.fillStyle=col;ctx.fill();ctx.globalAlpha=1}}});
 c._geo={P,pw,t0,t1};
 let hi=null;
 if(S.hoverT!=null&&S.hoverT>=t0-gap&&S.hoverT<=t1+gap){hi=nearest(times,S.hoverT);const x=Math.round(X(times[hi]))+.5;
  ctx.strokeStyle=css('--muted');ctx.setLineDash([3,3]);ctx.beginPath();ctx.moveTo(x,P.t);ctx.lineTo(x,P.t+ph);ctx.stroke();ctx.setLineDash([]);
  series.forEach(s=>{const v=s.values[hi];if(v==null)return;ctx.fillStyle=css(s.color);ctx.beginPath();ctx.arc(x,Y(v),3.5,0,7);ctx.fill()})}
 return hi??times.length-1;
}
function legend(id,items,t){$(id).innerHTML=items.map(([n,c,v])=>`<span><i style="background:var(${c})"></i>${esc(n)} <b>${v}</b></span>`).join('')+
 (t?`<span class="muted">${tstr(t)}</span>`:'')}
function windowStart(){const w=+$('win').value;if(!w)return 0;
 return Math.max(S.samples.at(-1)?.t||0,S.details.at(-1)?.t||0)-w}
function win(arr){const cut=windowStart();if(!cut)return arr;let i=0;while(i<arr.length&&arr[i].t<cut)i++;return arr.slice(i)}
const MARK={internet:'--c3',vpn:'--c4',wifi_uplink:'--c2',usb_uplink:'--c5'};
const MARK_EV=/^(internet_|vpn_|wifi_connected$|wifi_disconnected$|usb_)/;
const markers=()=>S.events.filter(e=>MARK[e.category]&&MARK_EV.test(e.event)).map(e=>({t:e.t,color:MARK[e.category]}));
const GRP={teleport:['Teleport','--c4'],teleport_poll:['Teleport status polling','--c5'],monitor:['This monitor','--c2'],
 kernel:['Kernel threads','--c1'],other:['Other processes','--c3'],unattributed:['Interrupts & short-lived','--muted']};
const fmtPct=v=>v==null?'–':(+v).toFixed(v<10?1:0)+'%';
const wanName=i=>S.state?.wans?.find(w=>w.iface===i)?.kind||i;

function ifaceList(){
 const names=[...new Set(S.samples.slice(-60).flatMap(s=>Object.keys(s.net)))];
 const map=S.state?.ifaces;
 const keep=map&&Object.keys(map).length?names.filter(n=>map[n]||/^(tun|ppp|usb|wg)/.test(n)):names.filter(n=>!HIDE.test(n));
 return keep.sort((a,b)=>((map?.[a]?.order??9)-(map?.[b]?.order??9))||a.localeCompare(b));
}
const ifLabel=n=>S.state?.ifaces?.[n]?.label||n;

function renderCharts(){
 const d=win(S.samples),T=d.map(s=>s.t),gap=Math.max(3*S.interval,5),mk=markers(),hv=S.hoverT!=null;
 let i=draw('cpu',T,[{color:'--c1',values:d.map(s=>s.cpu)}],{max:100,fmt:v=>v+'%',fill:true,gap,markers:mk});
 if(i!=null)legend('lg-cpu',[['CPU','--c1',pct(d[i].cpu)],['Load 1m','--c2',d[i].load1??'–']],hv&&T[i]);
 i=draw('mem',T,[{color:'--c3',values:d.map(s=>s.mem_pct)}],{max:100,fmt:v=>v+'%',fill:true,gap,markers:mk});
 if(i!=null){const s=d[i];legend('lg-mem',[['Used','--c3',`${pct(s.mem_pct)} (${s.mem_used_mb??'–'} / ${s.mem_total_mb??'–'} MB)`]],hv&&T[i])}
 const f=S.iface;
 i=draw('net',T,[{color:'--c1',values:d.map(s=>s.net[f]?.[0]??null)},{color:'--c2',values:d.map(s=>s.net[f]?.[1]??null)}],{fmt:fmtBits,fill:true,gap,markers:mk});
 if(i!=null){const r=d[i].net[f]||[];legend('lg-net',[['RX','--c1',fmtBits(r[0])],['TX','--c2',fmtBits(r[1])]],hv&&T[i])}
 const D=win(S.details),DT=D.map(s=>s.t),dgap=Math.max(3*S.dinterval,25);
 const none=S.dinterval?'Waiting for the first detail poll…':'Detail polling is off (--detail-interval 0)';
 const lk=[...new Set(D.flatMap(s=>Object.keys(s.lat||{})))].sort((a,b)=>{const aw=S.state?.system?.active_wan;return((b===aw)-(a===aw))||a.localeCompare(b)});
 i=draw('lat',DT,lk.map((k,j)=>({color:PAL[j%5],values:D.map(s=>s.lat?.[k]??null)})),{fmt:v=>Math.round(v)+' ms',gap:dgap,markers:mk,empty:none});
 if(i!=null)legend('lg-lat',lk.map((k,j)=>[wanName(k),PAL[j%5],D[i].lat?.[k]!=null?D[i].lat[k]+' ms':(k in (D[i].lat||{})?'<span class="bad">no reply</span>':'–')]),hv&&DT[i]);
 const ck=[...new Set(D.flatMap(s=>Object.keys(s.cu||{})))].sort();
 i=draw('cu',DT,ck.map((k,j)=>({color:PAL[j%5],values:D.map(s=>s.cu?.[k]??null)})),{max:100,fmt:v=>v+'%',gap:dgap,markers:mk,empty:none});
 if(i!=null)legend('lg-cu',[...ck.map((k,j)=>[k,PAL[j%5],pct(D[i].cu?.[k])]),['Wi-Fi clients','--muted',D[i].ncl??'–']],hv&&DT[i]);
 i=draw('usig',DT,[{color:'--c2',values:D.map(s=>s.usig)}],{min:-90,max:-20,fmt:v=>v+' dBm',gap:dgap,markers:mk,
  empty:S.state?'No Wi-Fi uplink connected':none});
 if(i!=null){const w=S.state?.wans?.find(w=>w.signal!=null&&w.connected);legend('lg-usig',[[w?w.kind:'Signal','--c2',sig(D[i].usig)]],hv&&DT[i])}
 const B=D.filter(s=>s.cpu_all!=null),BT=B.map(s=>s.t),bnone=S.dinterval?'Needs two detail polls…':none;
 i=draw('cpubk',BT,[{color:'--c1',values:B.map(s=>s.cpu_us)},{color:'--c2',values:B.map(s=>s.cpu_sy)},{color:'--c5',values:B.map(s=>s.cpu_si)}],
  {fmt:fmtPct,gap:dgap,markers:mk,empty:bnone});
 if(i!=null)legend('lg-cpubk',[['User','--c1',fmtPct(B[i].cpu_us)],['System','--c2',fmtPct(B[i].cpu_sy)],['IRQ + softirq','--c5',fmtPct(B[i].cpu_si)],['Total','--muted',fmtPct(B[i].cpu_all)]],hv&&BT[i]);
 const gk=Object.keys(GRP);
 i=draw('cpugrp',BT,gk.map(k=>({color:GRP[k][1],values:B.map(s=>s.grp?.[k]??0)})),{fmt:fmtPct,gap:dgap,markers:mk,empty:bnone});
 if(i!=null)legend('lg-cpugrp',gk.map(k=>[GRP[k][0],GRP[k][1],fmtPct(B[i].grp?.[k]??0)]),hv&&BT[i]);
 renderCost();
}

function ols(pts,keys){ // least squares y = b0 + b1*x1 (+ b2*x2)
 const n=pts.length,k=keys.length+1,X=pts.map(p=>[1,...keys.map(c=>p[c])]),y=pts.map(p=>p.y);
 const A=[...Array(k)].map((_,i)=>[...Array(k)].map((_,j)=>X.reduce((s,r)=>s+r[i]*r[j],0)));
 const v=[...Array(k)].map((_,i)=>X.reduce((s,r,m)=>s+r[i]*y[m],0));
 for(let c=0;c<k;c++){let p=c;for(let r=c+1;r<k;r++)if(Math.abs(A[r][c])>Math.abs(A[p][c]))p=r;
  [A[c],A[p]]=[A[p],A[c]];[v[c],v[p]]=[v[p],v[c]];if(Math.abs(A[c][c])<1e-9)return null;
  for(let r=0;r<k;r++)if(r!==c){const f=A[r][c]/A[c][c];for(let j=c;j<k;j++)A[r][j]-=f*A[c][j];v[r]-=f*v[c]}}
 const b=v.map((x,i)=>x/A[i][i]),ym=y.reduce((a,c)=>a+c,0)/n;
 const ssr=pts.reduce((s,p,m)=>s+(y[m]-X[m].reduce((a,x,j)=>a+x*b[j],0))**2,0),sst=y.reduce((s,c)=>s+(c-ym)**2,0);
 return{b,r2:sst?1-ssr/sst:0,n};
}
function renderCost(){
 const c=$('tcost'),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,W=c.clientWidth,H=c.clientHeight;
 c.width=W*dpr;c.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);ctx.font='11px system-ui,sans-serif';
 const B=win(S.details).filter(s=>s.cpu_all!=null&&s.vpn_bps!=null);
 const pts=B.map(s=>({x:s.vpn_bps*8/1e6,z:(s.nonvpn_bps||0)*8/1e6,y:(s.cpu_sy||0)+(s.cpu_si||0),
  tp:(s.grp?.teleport||0),tq:(s.grp?.teleport_poll||0),all:s.cpu_all,vpn:s.vpn,wan:(s.wan_bps||0)*8/1e6}));
 const P={l:46,r:10,t:8,b:30},pw=W-P.l-P.r,ph=H-P.t-P.b;
 if(pts.length<3){ctx.fillStyle=css('--muted');ctx.fillText('Collecting data…',P.l,P.t+ph/2);$('tcost-txt').innerHTML='';return}
 const xm=niceMax(Math.max(1,...pts.map(p=>p.x))*1.05),ym=niceMax(Math.max(1,...pts.map(p=>p.y))*1.1);
 const X=x=>P.l+x/xm*pw,Y=y=>P.t+ph-y/ym*ph;
 ctx.strokeStyle=css('--grid');ctx.fillStyle=css('--muted');ctx.textAlign='right';ctx.textBaseline='middle';
 for(let i=0;i<=4;i++){const v=ym*i/4,y=Math.round(Y(v))+.5;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(W-P.r,y);ctx.stroke();ctx.fillText(fmtPct(v),P.l-6,y)}
 ctx.textAlign='center';ctx.textBaseline='top';
 for(let i=0;i<=4;i++){const v=xm*i/4;ctx.fillText((+v.toFixed(1))+'',X(v),P.t+ph+4)}
 ctx.fillText('VPN throughput (Mb/s) → vs kernel CPU (system + softirq)',P.l+pw/2,P.t+ph+17);
 ctx.fillStyle=css('--c4');ctx.globalAlpha=.55;for(const p of pts){ctx.beginPath();ctx.arc(X(p.x),Y(p.y),2.6,0,7);ctx.fill()}ctx.globalAlpha=1;
 const xs=pts.map(p=>p.x),zs=pts.map(p=>p.z),spread=a=>Math.max(...a)-Math.min(...a);
 const corr=(()=>{const n=xs.length,mx=xs.reduce((a,b)=>a+b,0)/n,mz=zs.reduce((a,b)=>a+b,0)/n;let sxz=0,sxx=0,szz=0;
  for(let i=0;i<n;i++){sxz+=(xs[i]-mx)*(zs[i]-mz);sxx+=(xs[i]-mx)**2;szz+=(zs[i]-mz)**2}return sxx&&szz?sxz/Math.sqrt(sxx*szz):1})();
 const ok=spread(xs)>=2&&pts.length>=6;
 let two=ok&&spread(zs)>=2&&pts.length>=10&&Math.abs(corr)<0.9,fit=two?ols(pts,['x','z']):null; // separate the two only if they vary independently
 if(!fit){two=false;fit=ok?ols(pts,['x']):null}
 if(fit){const zbar=two?zs.reduce((a,b)=>a+b,0)/zs.length:0,f=x=>fit.b[0]+fit.b[1]*x+(two?fit.b[2]*zbar:0);
  ctx.strokeStyle=css('--c4');ctx.lineWidth=1.8;ctx.beginPath();ctx.moveTo(X(0),Y(Math.max(0,f(0))));ctx.lineTo(X(xm),Y(Math.max(0,Math.min(ym,f(xm)))));ctx.stroke()}
 const avg=a=>a.length?a.reduce((x,y)=>x+y,0)/a.length:null;
 const tp=avg(pts.map(p=>p.tp)),tq=avg(pts.map(p=>p.tq));
 let on=pts.filter(p=>p.vpn===1&&p.wan<1).map(p=>p.all),off=pts.filter(p=>p.vpn===0&&p.wan<1).map(p=>p.all),qlab=' while idle (WAN under 1 Mb/s)';
 if(on.length<3||off.length<3){on=pts.filter(p=>p.vpn===1).map(p=>p.all);off=pts.filter(p=>p.vpn===0).map(p=>p.all);qlab=''}
 const rows=[[`Teleport processes`,`<b>${fmtPct(tp)}</b> of CPU on average, plus <b>${fmtPct(tq)}</b> for status polling by other daemons`]];
 if(fit){const per10=fit.b[1]*10;
  rows.push(['VPN traffic',`≈ <b>${per10.toFixed(1)}%</b> extra kernel CPU per 10 Mb/s through the tunnel (encryption + forwarding; R² ${fit.r2.toFixed(2)}, ${fit.n} points)`]);
  if(two)rows.push(['Non-VPN traffic',`≈ <b>${(fit.b[2]*10).toFixed(1)}%</b> per 10 Mb/s, so the encryption premium is ≈ ${((fit.b[1]-fit.b[2])*10).toFixed(1)}% per 10 Mb/s`]);
  rows.push(['At 0 Mb/s',`≈ ${fmtPct(Math.max(0,fit.b[0]))} kernel CPU. This is the router's baseline, mostly not Teleport; see "VPN up vs down"`]);
  const quiet=pts.filter(p=>p.wan<1).map(p=>p.all),base=quiet.length>=3?avg(quiet):Math.min(...pts.map(p=>p.all));
  if(fit.b[1]>0)rows.push(['Ceiling',`CPU would reach 100% at ≈ <b>${Math.round((100-base)/(fit.b[1]))} Mb/s</b> through the tunnel, from a ${fmtPct(base)} baseline (projected)`]);
 }else rows.push(['VPN traffic',`<span class="muted">Needs a wider range of VPN throughput (at least 2 Mb/s spread). Run a speed test through the tunnel.</span>`]);
 if(on.length>=3&&off.length>=3)rows.push(['VPN up vs down',`total CPU ${fmtPct(avg(on))} with the VPN up vs ${fmtPct(avg(off))} with it down${qlab}`]);
 $('tcost-txt').innerHTML=`<dl>${rows.map(([k,v])=>`<dt>${k}</dt><dd style="white-space:normal">${v}</dd>`).join('')}</dl>
  <div class="muted" style="font-size:12px;margin-top:6px">Percentages are of the whole CPU (all cores), over the selected window. WireGuard's encryption runs in kernel workers and softirq shared with normal routing, so it's estimated from how kernel CPU rises with tunnel traffic. For a direct comparison, turn Teleport off for a few minutes and use "VPN up vs down".</div>`;
}

function tile(id,v,s,cls){$(id).innerHTML=`<div class="v ${cls||''}">${v}</div><div class="s">${s||'&nbsp;'}</div>`}
function table(id,head,rows,opt={}){
 if(!rows.length){$(id).innerHTML=`<div class="empty">${opt.empty||'Nothing to show'}</div>`;return}
 $(id).innerHTML=`<table><thead><tr>${head.map(h=>`<th class="${h.startsWith('#')?'n':''}">${h.replace(/^#/,'')}</th>`).join('')}</tr></thead>`+
  `<tbody class="${opt.pick?'pick':''}">${rows.map(r=>`<tr${r.attrs||''}>${r.map((c,i)=>`<td class="${head[i].startsWith('#')?'n':''}">${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`}
const join=a=>a.filter(x=>x!=null&&x!==false&&x!=='').join(' · ');

function renderInfo(){
 const st=S.state,last=S.samples.at(-1),cut=windowStart();
 tile('t-sys',last?`${pct(last.cpu)} CPU · ${pct(last.mem_pct)} mem`:'–',
  esc(join([st?.system?.model,st?.system?.firmware&&'fw '+st.system.firmware,st?.system?.satisfaction!=null&&'experience '+Math.round(st.system.satisfaction)+'%'])));
 if(!st){for(const t of['t-net','t-vpn','t-wifi'])tile(t,'–',S.dinterval?'Waiting for detail poll…':'Detail polling off');
  for(const t of['wans','vpn','clients','vaps','radios','nbrs'])$(t).innerHTML='<div class="empty">No detail data yet</div>'}
 else{
  const aw=st.wans.find(w=>w.active),backups=st.wans.filter(w=>!w.active&&w.connected).length;
  const off=st.system.internet===false||!aw;
  tile('t-net',off?'Offline':esc(aw.kind),aw?esc(join([aw.portal&&'portal '+aw.portal,aw.latency!=null&&aw.latency+' ms',aw.signal!=null&&aw.signal+' dBm',backups?backups+' backup'+(backups>1?'s':'')+' ready':null])):'',off?'bad':'ok');
  const tp=st.vpn.teleport,wgs=Object.entries(st.vpn.wg||{});
  const drops=S.events.filter(e=>e.category==='vpn'&&e.event==='vpn_off'&&e.t>=cut&&/CONNECTING|DISCONNECTED/.test(e.details?.new||'')).length;
  if(tp&&tp.state){const up=tp.state==='CONNECTED';
   tile('t-vpn','Teleport · '+esc(cap(tp.state)),esc(join([tp.site_name,up&&'up '+fmtDur(tp.uptime_seconds),drops?drops+' drop'+(drops>1?'s':'')+' in window':null])),up?'ok':'warn')}
  else if(wgs.length){const w=wgs[0][1],up=w.handshake_age!=null&&w.handshake_age<180;
   tile('t-vpn','WireGuard · '+(up?'Connected':'Stale'),'handshake '+(w.handshake_age!=null?fmtDur(w.handshake_age)+' ago':'never'),up?'ok':'warn')}
  else tile('t-vpn','Off','No VPN active');
  const aps=st.vaps.filter(v=>v.usage==='user'),nw=st.clients.filter(c=>!c.wired).length,ess=[...new Set(aps.map(v=>v.essid))];
  tile('t-wifi',`${nw} Wi-Fi client${nw===1?'':'s'}`,esc(join([ess.join(', '),st.radios.map(r=>`${r.band} ch ${r.channel??'?'} ${r.cu_total??'?'}% busy`).join(', ')])));

  table('wans',['Uplink','Status','IP','Portal','#Latency','#Signal','Upstream device'],st.wans.map(w=>{
   const r=[`<span class="dot" style="background:var(${w.active?'--ok':w.connected?'--c1':'--grid'})"></span>${esc(w.kind)}`,
    w.active?'Active':w.connected?'Standby':'<span class="muted">Not connected</span>',esc(w.ip||'–'),esc(w.portal||'–'),
    w.latency!=null?`<span title="${esc(Object.entries(w.targets||{}).map(([k,v])=>k+': '+v+' ms').join('\n'))}">${w.latency} ms</span>`:(w.connected?'<span class="bad">no reply</span>':'–'),
    sig(w.signal),esc(w.neighbour||'–')];if(!w.connected)r.attrs=' class="faint"';return r}));

  const kv=rows=>`<dl>${rows.filter(r=>r[1]!=null&&r[1]!=='').map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  let vh='';
  if(tp&&tp.state)vh+=kv([['Teleport',`<span class="${tp.state==='CONNECTED'?'ok':'warn'}">${esc(tp.detailed_status||tp.state)}</span>`],['Site',esc(tp.site_name)],
   ['Up for',fmtDur(tp.uptime_seconds)],['Client IP',esc(tp.client_ip)],['Endpoint',esc(tp.endpoint)],
   ['Traffic',`↓ ${fmtBytes(tp.rx_bytes)} · ↑ ${fmtBytes(tp.tx_bytes)}`],['Kill switch',tp.killswitch_enabled?'On':'Off'],
   ['Internet via VPN',esc(tp.internet_state)],['Drops in window',String(drops)]]);
  for(const[n,w]of wgs)vh+=kv([['Tunnel',esc(n)],['Last handshake',w.handshake_age!=null?fmtDur(w.handshake_age)+' ago':'never'],
   ['Transfer',`↓ ${fmtBytes(w.rx_bytes)} · ↑ ${fmtBytes(w.tx_bytes)}`]]).replace('<dl>','<dl style="margin-top:10px">');
  $('vpn').innerHTML=vh||'<div class="empty">No VPN configured or running</div>';

  const cl=[...st.clients].sort((a,b)=>(a.wired-b.wired)||((b.signal??-999)-(a.signal??-999)));
  $('ncl').textContent=`${nw} Wi-Fi · ${st.clients.length-nw} wired`;
  table('clients',['Name','IP','Connection','#Signal','#Link ↓ / ↑','#Now ↓ / ↑','#Total ↓ / ↑','Standard','#Connected','#Experience'],cl.map(c=>[
   c.name?esc(c.name):`<span class="muted">${esc(c.mac)}</span>`,esc(c.ip||'–'),esc(c.conn),c.wired?'–':sig(c.signal),
   c.wired?(c.tx_rate?fmtLink(c.tx_rate):'–'):`${fmtLink(c.tx_rate)} / ${fmtLink(c.rx_rate)}`,
   (c.down_bps!=null?`${fmtBits(c.down_bps)} / ${fmtBits(c.up_bps)}`:'–')+(c.shared?`<div class="muted" style="font-size:11.5px">port total, shared by ${c.shared}</div>`:''),
   (c.tx_bytes!=null?`${fmtBytes(c.tx_bytes)} / ${fmtBytes(c.rx_bytes)}`:'–')+(c.wired&&c.tx_bytes!=null?`<div class="muted" style="font-size:11.5px">port since boot</div>`:''),
   esc(c.std||(c.wired?'Ethernet':'–')),fmtDur(c.uptime),exp(c.satisfaction)]),
   {empty:'No clients connected'});

  table('vaps',['Network','Role','Band','#Channel','#Clients','#Tx power','#Experience'],st.vaps.map(v=>[esc(v.essid||'(hidden)'),
   v.usage==='user'?'Access point':v.usage==='wireless-bridge'?'Uplink (client)':esc(v.usage),esc(v.band),
   `${esc(v.channel)} / ${esc(v.bw)} MHz`,v.usage==='user'?esc(v.num_sta):'–',v.tx_power!=null?esc(v.tx_power)+' dBm':'–',exp(v.satisfaction)]));
  table('radios',['Band','#Channel','#Busy','#Own tx / rx','#Noise floor','#Max power','#Experience'],st.radios.map(r=>[esc(r.band),
   `${esc(r.channel??'–')} / ${esc(r.bw??'–')} MHz`,pct(r.cu_total),`${r.cu_self_tx??'–'}% / ${r.cu_self_rx??'–'}%`,
   r.noise!=null?esc(r.noise)+' dBm':'–',r.max_txpower!=null?esc(r.max_txpower)+' dBm':'–',exp(r.satisfaction)]));
  const PW=win(S.details).filter(s=>s.top),agg={};
  PW.forEach((s,k)=>{for(const[l,g,v]of s.top){const a=agg[l]||(agg[l]={g,sum:0,now:null});a.sum+=v;if(k===PW.length-1)a.now=v}});
  const pr=Object.entries(agg).map(([l,a])=>[l,a.g,a.now,a.sum/PW.length]).sort((a,b)=>b[3]-a[3]).slice(0,14);
  table('procs',['Process','Group','#Now','#Window avg'],pr.map(([l,g,n,a])=>[esc(l),
   `<span class="chip" style="color:var(${GRP[g]?.[1]||'--muted'})">${esc(GRP[g]?.[0]||g)}</span>`,fmtPct(n),fmtPct(a)]),
   {empty:'Needs two detail polls'});
  table('nbrs',['Network','BSSID','Band','#Ch','#Signal','Security','Device'],st.neighbours.map(n=>[n.essid?esc(n.essid):'<span class="muted">(hidden)</span>',
   `<span class="muted">${esc(n.bssid)}</span>`,esc(n.band),esc(n.channel),sig(n.signal),esc(n.security),esc(n.model||'')]),{empty:'No scan results (the UTR only scans its uplink channel)'});
 }
 // interface picker + table
 const names=ifaceList(),d=win(S.samples),peak={};
 for(const s of d)for(const[k,[rx,tx]]of Object.entries(s.net)){const p=peak[k]||(peak[k]=[0,0]);p[0]=Math.max(p[0],rx);p[1]=Math.max(p[1],tx)}
 if(!S.iface||!names.includes(S.iface))S.iface=names.includes(st?.system?.active_wan)?st.system.active_wan:names[0]||null;
 const sel=$('iface'),key=names.map(n=>n+'='+ifLabel(n)).join();
 if(sel.dataset.k!==key){sel.innerHTML=names.map(n=>`<option value="${esc(n)}">${esc(ifLabel(n))}</option>`).join('');sel.dataset.k=key}
 sel.value=S.iface||'';
 const lastNet=S.samples.at(-1)?.net||{};
 table('ifs',['Interface','#RX','#TX','#Peak RX','#Peak TX'],names.map(n=>{const r=[`${esc(ifLabel(n))} <span class="muted">${esc(n)}</span>`,
  fmtBits(lastNet[n]?.[0]),fmtBits(lastNet[n]?.[1]),fmtBits(peak[n]?.[0]),fmtBits(peak[n]?.[1])];
  r.attrs=` data-i="${esc(n)}"${n===S.iface?' class="sel"':''}`;return r}),{pick:true});
 renderEvents();
}

function vpnText(s){const on=String(s||'').split(';').map(p=>p.split('=')).filter(([k,v])=>v&&v!=='missing');
 return on.length?on.map(([k,v])=>`${k==='teleport'?'Teleport':k==='openvpn'?'OpenVPN':k==='wireguard'?'WireGuard':k} ${v.toLowerCase()}`).join(', '):'no VPN'}
function evMsg(e){const d=e.details||{},k=e.category+'/'+e.event;
 switch(k){
  case'internet/internet_on':return`Internet up via ${wanName(d.iface)}${d.portal_state?' ('+d.portal_state+')':''}`;
  case'internet/internet_off':return`Internet down${d.new?' ('+d.new+')':''}`;
  case'wifi_uplink/wifi_connected':return`Wi-Fi uplink connected to ${d.ssid||d.bssid||'?'}${d.freq?' ('+d.freq+' MHz)':''}`;
  case'wifi_uplink/wifi_disconnected':return'Wi-Fi uplink disconnected';
  case'uplink_dhcp/dhcp_bound':return`${wanName(d.iface)} got ${d.ip}${d.router?' via '+d.router:''}`;
  case'uplink_dhcp/dhcp_leasefail':return`${wanName(d.iface)}: no DHCP lease`;
  case'uplink_dhcp/dhcp_deconfig':return`${wanName(d.iface)}: address released`;
  case'collector/started':return'Event logging started';
 }
 if(e.category==='vpn')return'VPN: '+vpnText(d.new);
 if(e.category==='wifi_uplink'&&d.supplicant_event)return`Wi-Fi uplink: ${d.supplicant_event}${d.ssid?' ('+d.ssid+')':''}`;
 if(e.category==='usb_uplink')return'USB tether '+(d.new||e.event.replace('usb_',''));
 if(e.category==='bt')return'Bluetooth '+(d.new||e.event.replace('bt_',''));
 return e.event.replace(/_/g,' ')+(Object.keys(d).length?' · '+Object.entries(d).map(([a,b])=>a+'='+b).join(' '):'');
}
function renderEvents(){
 const cats=[...new Set(S.events.map(e=>e.category))].sort(),sel=$('evcat'),key=cats.join();
 if(sel.dataset.k!==key){const v=sel.value;sel.innerHTML='<option value="">All categories</option>'+cats.map(c=>`<option>${esc(c)}</option>`).join('');sel.value=v;sel.dataset.k=key}
 const cat=sel.value,dhcp=$('evdhcp').checked;
 const ev=S.events.filter(e=>(!cat||e.category===cat)&&(dhcp||e.event!=='dhcp_leasefail')).slice(-300).reverse();
 table('events',['Time','Category','Event'],ev.map(e=>[`<span class="muted">${dtstr(e.t)}</span>`,
  `<span class="chip"${MARK[e.category]?` style="color:var(${MARK[e.category]})"`:''}>${esc(e.category)}</span>`,esc(evMsg(e))]),
  {empty:S.dinterval?'No router events yet':'Detail polling is off'});
}

async function poll(){
 try{const r=await fetch(`/api/data?since=${S.last}&dsince=${S.dlast}&eseq=${S.eseq}`),j=await r.json();
  S.interval=j.interval;S.dinterval=j.dinterval;S.history=j.history;
  if(S.gen!=null&&j.status.reset_gen!==S.gen){S.samples=[];S.details=[];S.events=[];S.iface=null}
  S.gen=j.status.reset_gen;S.db=j.status.db;
  if(j.samples.length){S.samples.push(...j.samples);S.last=j.samples.at(-1).t;
   if(S.samples.length>S.history)S.samples.splice(0,S.samples.length-S.history)}
  if(j.details.length){S.details.push(...j.details);S.dlast=j.details.at(-1).t;
   if(S.details.length>S.history)S.details.splice(0,S.details.length-S.history)}
  if(j.events.length){S.events.push(...j.events);S.eseq=j.events.at(-1).seq;S.events.sort((a,b)=>a.t-b.t);
   if(S.events.length>1000)S.events.splice(0,S.events.length-1000)}
  if(j.state)S.state=j.state;
  const st=j.status,sys=S.state?.system;
  $('host').textContent=(sys?.hostname?sys.hostname+' · ':'')+st.host+(st.method?` · via ${st.method}`:'')+(st.detail_ms!=null?` · detail ${st.detail_ms} ms`:'');
  $('dot').style.background=css(st.connected?'--ok':'--bad');
  $('st').textContent=st.connected?(st.detail_error?'live (detail error: '+st.detail_error+')':'live'):(st.error?'error: '+st.error:'connecting…');
  $('up').textContent=st.uptime||'';
  $('db').textContent=st.db?`· db ${st.db} (${st.db_rows.toLocaleString()} rows)`:'· db off';
  renderInfo();renderCharts();
 }catch(e){$('dot').style.background=css('--bad');$('st').textContent='web server unreachable';console.error(e)}
 setTimeout(poll,Math.max(1000,S.interval*1000));
}
for(const id of['cpu','mem','net','lat','cu','usig','cpubk','cpugrp']){const c=$(id);
 c.addEventListener('mousemove',e=>{const g=c._geo;if(!g)return;S.hoverT=g.t0+(e.offsetX-g.P.l)/g.pw*(g.t1-g.t0);renderCharts()});
 c.addEventListener('mouseleave',()=>{S.hoverT=null;renderCharts()})}
$('iface').onchange=e=>{S.iface=e.target.value;renderInfo();renderCharts()};
$('ifs').onclick=e=>{const tr=e.target.closest('tr[data-i]');if(tr){S.iface=tr.dataset.i;renderInfo();renderCharts()}};
$('evcat').onchange=renderEvents;$('evdhcp').onchange=renderEvents;
$('reset').onclick=async()=>{
 if(!confirm('Delete all collected history'+(S.db?' (including the SQLite database)':'')+'? This cannot be undone.'))return;
 const r=await fetch('/api/reset',{method:'POST',headers:{'X-UTR-Reset':'1'}});
 if(r.ok){S.samples=[];S.details=[];S.events=[];S.last=S.dlast=0;S.iface=null;renderInfo();renderCharts()}else alert('Reset failed: '+r.status)};
$('win').onchange=()=>{renderInfo();renderCharts()};window.addEventListener('resize',renderCharts);
$('skin').value=document.documentElement.dataset.skin||'classic';
$('skin').onchange=e=>{document.documentElement.dataset.skin=e.target.value;
 try{localStorage.setItem('utr.skin',e.target.value)}catch(err){}
 const st=S.last&&document.getElementById('dot');renderInfo();renderCharts();
 if(st)st.style.background=css(($('st').textContent||'').startsWith('live')?'--ok':'--bad')};
function setCpu(open){$('cpucard').classList.toggle('open',open);const b=$('cpumore');
 b.textContent=open?'Hide breakdown ▾':'Show breakdown ▸';b.setAttribute('aria-expanded',String(open));
 try{localStorage.setItem('utr.cpuBreakdown',open?'1':'0')}catch(e){}
 renderCharts()}
$('cpumore').onclick=()=>setCpu(!$('cpucard').classList.contains('open'));
setCpu((()=>{try{return localStorage.getItem('utr.cpuBreakdown')==='1'}catch(e){return false}})());
poll();
</script></body></html>"""


def make_handler(collector):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.debug("http: " + fmt, *args)

        def _send(self, code, body, ctype):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _csv(self):
            store = collector.store
            src = store.iter_all if store else (lambda: iter(collector.snapshot()["samples"]))
            ifaces = sorted({k for s in src() for k in s["net"]})
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", 'attachment; filename="utr-monitor.csv"')
            self.end_headers()

            def cell(v):
                return "" if v is None else str(v)
            out = ["time,cpu_pct,mem_pct,mem_used_mb,load1" +
                   "".join(f",{i}_rx_bps,{i}_tx_bps" for i in ifaces)]
            for s in src():
                row = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["t"])),
                       cell(s["cpu"]), cell(s["mem_pct"]), cell(s["mem_used_mb"]), cell(s["load1"])]
                for i in ifaces:
                    rx, tx = s["net"].get(i, (None, None))
                    row += ["" if rx is None else f"{rx * 8:.0f}", "" if tx is None else f"{tx * 8:.0f}"]
                out.append(",".join(row))
                if len(out) >= 5000:
                    self.wfile.write(("\n".join(out) + "\n").encode())
                    out = []
            if out:
                self.wfile.write(("\n".join(out) + "\n").encode())

        def do_POST(self):
            if urlparse(self.path).path != "/api/reset":
                return self._send(404, "not found", "text/plain")
            # A custom header forces a CORS preflight, so other websites can't trigger a reset.
            if self.headers.get("X-UTR-Reset") != "1":
                return self._send(403, "missing X-UTR-Reset header", "text/plain")
            collector.reset()
            self._send(200, '{"ok": true}', "application/json")

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif u.path == "/api/data":
                q = parse_qs(u.query)

                def num(k, cast=float):
                    try:
                        return cast(q.get(k, ["0"])[0])
                    except ValueError:
                        return cast(0)
                snap = collector.snapshot(num("since"), num("dsince"), num("eseq", int))
                self._send(200, json.dumps(snap), "application/json")
            elif u.path == "/api/state":
                self._send(200, json.dumps(collector.snapshot(time.time(), time.time(), 1 << 60)["state"]),
                           "application/json")
            elif u.path == "/api/export.csv":
                self._csv()
            else:
                self._send(404, "not found", "text/plain")

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Graph a UniFi Travel Router's CPU/MEM/network via SSH.")
    ap.add_argument("host", nargs="?", help="UTR IP address / hostname")
    ap.add_argument("-u", "--user", default="ui", help="SSH user (default: ui)")
    ap.add_argument("-p", "--password", help="SSH password (else $UTR_PASSWORD, else the saved one, else prompt)")
    ap.add_argument("--no-save-password", action="store_true",
                    help="don't save a typed password to the system keychain")
    ap.add_argument("--forget-password", action="store_true",
                    help="remove the saved password for this user@host and exit")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("-i", "--interval", type=float, default=2.0, help="poll interval seconds (default 2)")
    ap.add_argument("--detail-interval", type=float, default=10.0,
                    help="seconds between UniFi detail polls (mca-dump, VPN, events); 0 disables (default 10)")
    ap.add_argument("--history", type=int, default=3600, help="points kept in memory per series (default 3600)")
    ap.add_argument("--iface", action="append", help="only track this interface (repeatable)")
    ap.add_argument("--bind", default="127.0.0.1", help="web server bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="web server port (default 8080)")
    ap.add_argument("--db", help="SQLite file (default: utr-monitor-<host>.db in the current directory)")
    ap.add_argument("--no-db", action="store_true", help="don't persist samples to SQLite")
    ap.add_argument("--retention-days", type=float, default=30,
                    help="prune DB rows older than this many days (0 = keep forever; default 30)")
    ap.add_argument("--once", action="store_true",
                    help="run one detail poll, print the parsed state as JSON and exit (for debugging)")
    ap.add_argument("--demo", action="store_true", help="generate fake data, no SSH")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S",
                        stream=sys.stderr)
    if not a.verbose:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if a.demo:
        runner = DemoRunner()
    else:
        if not a.host:
            ap.error("host is required (or use --demo)")
        if a.forget_password:
            if forget_password(a.user, a.host):
                print(f"Removed the saved password for {a.user}@{a.host}")
            else:
                print(f"No saved password for {a.user}@{a.host}" +
                      ("" if _keyring() else " (the keyring package isn't installed)"))
            return
        pw, source = resolve_password(a.user, a.host, a.password)
        runner = SSHRunner(a.host, a.user, pw, port=a.ssh_port, timeout=20)
        login(runner, source, save=not a.no_save_password)

    if a.once:
        col = Collector(runner, 1, 10)
        t0 = time.time()
        state = col.poll_detail()
        state["_events"] = list(col.events)[-15:]
        state["_detail_ms"] = round((time.time() - t0) * 1000)
        print(json.dumps(state, indent=2))
        runner.close()
        return

    db_path = None
    if not a.no_db:
        if a.db:
            db_path = a.db
        elif not a.demo:  # keep fake data out of the real DB unless --db is given
            db_path = "utr-monitor-" + re.sub(r"[^A-Za-z0-9._-]", "_", a.host) + ".db"
    store = Store(db_path, a.retention_days) if db_path else None
    if store:
        log.info("Persisting to %s (%d rows, retention %s)", db_path, store.count,
                 f"{a.retention_days:g} days" if a.retention_days else "forever")
    col = Collector(runner, max(0.5, a.interval), a.history, a.iface, store,
                    max(0.0, a.detail_interval) if a.detail_interval <= 0 else max(5.0, a.detail_interval))
    col.start()

    srv = ThreadingHTTPServer((a.bind, a.port), make_handler(col))
    log.info("Web UI:  http://%s:%d/   (CSV export: /api/export.csv)",
             "127.0.0.1" if a.bind in ("0.0.0.0", "") else a.bind, a.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        srv.server_close()
        runner.close()
        if store:
            store.close()


if __name__ == "__main__":
    main()
