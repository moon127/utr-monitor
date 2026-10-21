#!/usr/bin/env python3
"""
utr_monitor.py - Poll a UniFi Travel Router (UTR) over SSH and graph CPU,
memory and per-interface network throughput in a local web page.
 
Usage:
    pip install paramiko
    python3 utr_monitor.py 192.168.1.1                 # prompts for password
    python3 utr_monitor.py 192.168.1.1 -i 2 --port 8080
    UTR_PASSWORD=secret python3 utr_monitor.py 192.168.1.1
    python3 utr_monitor.py --demo                      # fake data, no device needed
    python3 utr_monitor.py 192.168.1.1 --no-db         # memory only, no SQLite
 
Then open http://127.0.0.1:8080/
 
How it collects:
  * Tries /proc (stat, meminfo, net/dev, loadavg) first - most accurate.
  * Falls back to BusyBox `top -bn1` + `ifconfig` if /proc reads are blocked.
  * Uses SSH exec channels; if the restricted shell rejects those, it falls
    back to a single interactive shell session with output markers.
  * Reconnects automatically with backoff if the SSH session drops.
"""
 
import argparse
import collections
import getpass
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
# Collector
# --------------------------------------------------------------------------- #
class Store:
    """SQLite persistence: one row per poll, interface rates stored as JSON."""

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
        self.db.commit()
        self.count = self.db.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        self._last_prune = 0.0
        self._prune()

    def _prune(self):
        if not self.retention:
            return
        cur = self.db.execute("DELETE FROM samples WHERE t < ?", (time.time() - self.retention,))
        self.db.commit()
        self.count -= max(cur.rowcount, 0)
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

    def recent(self, limit):
        with self.lock:
            rows = self.db.execute("SELECT * FROM (SELECT * FROM samples ORDER BY t DESC LIMIT ?) "
                                   "ORDER BY t", (limit,)).fetchall()
        return [self._row(r) for r in rows]

    def iter_all(self):
        conn = sqlite3.connect(self.path)  # separate reader; WAL lets it run alongside writes
        try:
            for r in conn.execute("SELECT * FROM samples ORDER BY t"):
                yield self._row(r)
        finally:
            conn.close()

    def reset(self):
        with self.lock:
            self.db.execute("DELETE FROM samples")
            self.db.commit()
            self.db.execute("VACUUM")
            self.count = 0

    def close(self):
        with self.lock:
            self.db.close()


class Collector(threading.Thread):
    def __init__(self, runner, interval, history, iface_filter=None, store=None):
        super().__init__(daemon=True)
        self.runner, self.interval = runner, interval
        self.samples = collections.deque(maxlen=history)
        self.iface_filter = set(iface_filter or [])
        self.lock = threading.Lock()
        self.status = {"connected": False, "error": None, "method": None,
                       "uptime": "", "host": getattr(runner, "host", "demo"),
                       "db": store.path if store else None, "db_rows": 0, "reset_gen": 0}
        self.store = store
        if store:
            self.samples.extend(store.recent(history))
            log.info("Loaded %d samples from %s", len(self.samples), store.path)
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
            time.sleep(max(0.0, self.interval - (time.time() - start)))
 
    def reset(self):
        with self.lock:
            self.samples.clear()
            if self.store:
                self.store.reset()
            self.status["reset_gen"] += 1
        log.info("History reset from web UI")

    def snapshot(self, since=0.0):
        with self.lock:
            data = [s for s in self.samples if s["t"] > since]
            st = dict(self.status)
            st["db_rows"] = self.store.count if self.store else 0
            return {"status": st, "interval": self.interval,
                    "history": self.samples.maxlen, "samples": data}
 
 
class DemoRunner:
    """Fakes /proc output so the UI can be tried without a device."""
    host = "demo"
    mode = "demo"
 
    def __init__(self):
        self.t0 = time.time()
        self.cpu = [0, 0]
        self.net = {"eth0": [0, 0], "wlan0": [0, 0], "br0": [0, 0]}
 
    def close(self):
        pass
 
    def run(self, cmd):
        el = time.time() - self.t0
        busy = int(30 + 25 * math.sin(el / 20) + random.uniform(0, 20))
        self.cpu[0] += busy
        self.cpu[1] += 100 - busy
        lines = [f"cpu  {self.cpu[0]} 0 0 {self.cpu[1]} 0 0 0 0"]
        avail = int(260000 + 20000 * math.sin(el / 45))
        mem = f"MemTotal: 512000 kB\nMemFree: 100000 kB\nMemAvailable: {avail} kB"
        rate = max(0, 4e6 + 3e6 * math.sin(el / 15) + random.uniform(-1e6, 1e6))
        for i, k in enumerate(self.net):
            self.net[k][0] += int(rate * (1 - i * 0.3))
            self.net[k][1] += int(rate * 0.2 * (1 + i * 0.5))
        nd = "Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n"
        nd += "".join(f"  {k}: {v[0]} 0 0 0 0 0 0 0 {v[1]} 0 0 0 0 0 0 0\n"
                      for k, v in self.net.items())
        return (f"{lines[0]}\n{SEP}\n{mem}\n{SEP}\n{nd}{SEP}\n"
                f"{busy / 50:.2f} 0.5 0.4 1/80 999\n{SEP}\n up {int(el)}s, load average: 0.5")
 
 
# --------------------------------------------------------------------------- #
# Web UI
# --------------------------------------------------------------------------- #
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UTR Monitor</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#6b7280;--grid:#e5e7eb;
 --c1:#2563eb;--c2:#d97706;--c3:#059669;--bad:#dc2626;--ok:#16a34a}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#181c24;--fg:#e6e8ee;
 --muted:#9097a3;--grid:#2a303b;--c1:#60a5fa;--c2:#fbbf24;--c3:#34d399;--bad:#f87171;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:14px 16px}
h1{font-size:17px;margin:0;font-weight:600}.muted{color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted);margin-right:6px}
.spacer{flex:1}select{background:var(--card);color:var(--fg);border:1px solid var(--grid);
 border-radius:6px;padding:4px 8px;font:inherit}
button{background:var(--card);color:var(--fg);border:1px solid var(--grid);border-radius:6px;padding:4px 10px;font:inherit;cursor:pointer}button:hover{border-color:var(--bad);color:var(--bad)}
main{display:grid;gap:14px;padding:0 16px 16px;grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}
@media (max-width:480px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--grid);border-radius:10px;padding:12px 14px}
.card h2{font-size:13px;margin:0 0 4px;font-weight:600;display:flex;gap:8px;align-items:center}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-variant-numeric:tabular-nums;min-height:20px}
.legend i{display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:5px;vertical-align:middle}
.big{font-size:22px;font-weight:600}
canvas{width:100%;height:200px;display:block;cursor:crosshair}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
td,th{text-align:right;padding:4px 6px;border-bottom:1px solid var(--grid)}td:first-child,th:first-child{text-align:left}
th{color:var(--muted);font-weight:500}tr.sel td{color:var(--c1);font-weight:600}tbody tr{cursor:pointer}
</style></head><body>
<header>
 <h1>UTR Monitor</h1><span id="host" class="muted"></span>
 <span><span id="dot" class="dot"></span><span id="st" class="muted">connecting…</span></span>
 <span id="up" class="muted"></span><span id="db" class="muted"></span><span class="spacer"></span>
 <label class="muted">Window <select id="win">
  <option value="300">5 min</option><option value="900" selected>15 min</option>
  <option value="3600">1 hour</option><option value="0">All</option></select></label>
 <button id="reset" title="Delete all collected history">Reset data</button>
</header>
<main>
 <div class="card"><h2>CPU</h2><div class="legend" id="lg-cpu"></div><canvas id="cpu"></canvas></div>
 <div class="card"><h2>Memory</h2><div class="legend" id="lg-mem"></div><canvas id="mem"></canvas></div>
 <div class="card"><h2>Throughput <select id="iface"></select></h2>
  <div class="legend" id="lg-net"></div><canvas id="net"></canvas></div>
 <div class="card"><h2>Interfaces (current)</h2>
  <table><thead><tr><th>Interface</th><th>RX</th><th>TX</th><th>Peak RX</th><th>Peak TX</th></tr></thead>
  <tbody id="tbl"></tbody></table></div>
</main>
<script>
const S={samples:[],last:0,iface:null,interval:2,history:3600,hover:{}};
const $=id=>document.getElementById(id);
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
function fmtBits(Bps){if(Bps==null)return'–';let b=Bps*8,u=['b/s','kb/s','Mb/s','Gb/s'],i=0;
 while(b>=1000&&i<u.length-1){b/=1000;i++}return b.toFixed(b<10&&i?2:b<100&&i?1:0)+' '+u[i]}
const pct=v=>v==null?'–':v.toFixed(1)+'%';
const tstr=t=>new Date(t*1000).toLocaleTimeString([], {hour12:false});
function niceMax(v){if(v<=0)return 1;const p=Math.pow(10,Math.floor(Math.log10(v)));
 for(const m of[1,2,2.5,5,10])if(m*p>=v)return m*p;return 10*p}
 
function draw(id,times,series,opt){
 const c=$(id),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1;
 const W=c.clientWidth,H=c.clientHeight;c.width=W*dpr;c.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);
 ctx.clearRect(0,0,W,H);ctx.font='11px system-ui,sans-serif';
 const P={l:62,r:10,t:8,b:20},pw=W-P.l-P.r,ph=H-P.t-P.b;
 c._geo=null;
 if(times.length<2){ctx.fillStyle=css('--muted');ctx.fillText('Waiting for data…',P.l,P.t+ph/2);return null}
 const t0=times[0],t1=times[times.length-1]||t0+1;
 let mx=opt.max;if(mx==null){let m=0;for(const s of series)for(const v of s.values)if(v!=null&&v>m)m=v;mx=niceMax(m*1.1)}
 const X=t=>P.l+(t-t0)/(t1-t0||1)*pw,Y=v=>P.t+ph-(v/mx)*ph;
 ctx.strokeStyle=css('--grid');ctx.fillStyle=css('--muted');ctx.lineWidth=1;ctx.textAlign='right';ctx.textBaseline='middle';
 for(let i=0;i<=4;i++){const v=mx*i/4,y=Math.round(Y(v))+.5;ctx.beginPath();ctx.moveTo(P.l,y);ctx.lineTo(W-P.r,y);ctx.stroke();
  ctx.fillText(opt.fmt(v),P.l-6,y)}
 ctx.textAlign='center';ctx.textBaseline='top';
 const n=Math.max(2,Math.floor(pw/90));for(let i=0;i<=n;i++){const t=t0+(t1-t0)*i/n;ctx.fillText(tstr(t),Math.min(Math.max(X(t),P.l+22),W-P.r-22),P.t+ph+5)}
 const gap=Math.max(3*S.interval,5); // break lines across collection gaps (e.g. restarts)
 series.forEach((s,si)=>{const col=css(s.color),segs=[];let cur=null;
  times.forEach((t,i)=>{const v=s.values[i];if(v==null||(i&&t-times[i-1]>gap))cur=null;if(v==null)return;
   if(!cur)segs.push(cur=[]);cur.push([X(t),Y(Math.min(v,mx))])});
  for(const g of segs){ctx.beginPath();g.forEach(([x,y],k)=>k?ctx.lineTo(x,y):ctx.moveTo(x,y));
   ctx.strokeStyle=col;ctx.lineWidth=1.6;ctx.stroke();
   if(si===0&&opt.fill){ctx.lineTo(g[g.length-1][0],P.t+ph);ctx.lineTo(g[0][0],P.t+ph);ctx.closePath();
    ctx.globalAlpha=.12;ctx.fillStyle=col;ctx.fill();ctx.globalAlpha=1}}});
 c._geo={P,pw,t0,t1,times};
 const h=S.hover[id];if(h!=null&&times[h]!=null){const x=Math.round(X(times[h]))+.5;ctx.strokeStyle=css('--muted');
  ctx.setLineDash([3,3]);ctx.beginPath();ctx.moveTo(x,P.t);ctx.lineTo(x,P.t+ph);ctx.stroke();ctx.setLineDash([]);
  series.forEach(s=>{const v=s.values[h];if(v==null)return;ctx.fillStyle=css(s.color);ctx.beginPath();ctx.arc(x,Y(Math.min(v,mx)),3.5,0,7);ctx.fill()})}
 return h!=null&&times[h]!=null?h:times.length-1;
}
function legend(id,items,t){$(id).innerHTML=items.map(([n,c,v])=>`<span><i style="background:var(${c})"></i>${n} <b>${v}</b></span>`).join('')+
 (t?`<span class="muted">${tstr(t)}</span>`:'')}
 
function view(){const w=+$('win').value;if(!w||!S.samples.length)return S.samples;
 const cut=S.samples[S.samples.length-1].t-w;return S.samples.filter(s=>s.t>=cut)}
 
function render(){
 const d=view(),T=d.map(s=>s.t);
 let i=draw('cpu',T,[{color:'--c1',values:d.map(s=>s.cpu)}],{max:100,fmt:v=>v+'%',fill:true});
 if(i!=null)legend('lg-cpu',[['CPU','--c1',pct(d[i].cpu)],['Load 1m','--c2',d[i].load1??'–']],S.hover.cpu!=null&&T[i]);
 i=draw('mem',T,[{color:'--c3',values:d.map(s=>s.mem_pct)}],{max:100,fmt:v=>v+'%',fill:true});
 if(i!=null){const s=d[i];legend('lg-mem',[['Used','--c3',`${pct(s.mem_pct)} (${s.mem_used_mb??'–'} / ${s.mem_total_mb??'–'} MB)`]],S.hover.mem!=null&&T[i])}
 const f=S.iface;
 i=draw('net',T,[{color:'--c1',values:d.map(s=>s.net[f]?.[0]??null)},{color:'--c2',values:d.map(s=>s.net[f]?.[1]??null)}],{fmt:fmtBits,fill:true});
 if(i!=null){const r=d[i].net[f]||[];legend('lg-net',[['RX','--c1',fmtBits(r[0])],['TX','--c2',fmtBits(r[1])]],S.hover.net!=null&&T[i])}
 // interface table + selector
 const names=[...new Set(d.flatMap(s=>Object.keys(s.net)))].sort();
 const peak={};for(const s of d)for(const[k,[rx,tx]]of Object.entries(s.net)){const p=peak[k]||(peak[k]=[0,0,0]);
  p[0]=Math.max(p[0],rx);p[1]=Math.max(p[1],tx);p[2]+=rx+tx}
 if(!S.iface&&names.length){S.iface=names.reduce((a,b)=>peak[b][2]>peak[a][2]?b:a);}
 const sel=$('iface');if(sel.dataset.k!==names.join()){sel.innerHTML=names.map(n=>`<option>${n}</option>`).join('');sel.dataset.k=names.join()}
 sel.value=S.iface||'';
 const last=d[d.length-1]?.net||{};
 $('tbl').innerHTML=names.map(n=>`<tr data-i="${n}" class="${n===S.iface?'sel':''}"><td>${n}</td><td>${fmtBits(last[n]?.[0])}</td><td>${fmtBits(last[n]?.[1])}</td><td>${fmtBits(peak[n][0])}</td><td>${fmtBits(peak[n][1])}</td></tr>`).join('');
}
 
async function poll(){
 try{const r=await fetch('/api/data?since='+S.last),j=await r.json();
  S.interval=j.interval;S.history=j.history;
  if(S.gen!=null&&j.status.reset_gen!==S.gen){S.samples=[];S.iface=null}S.gen=j.status.reset_gen;S.db=j.status.db;
  if(j.samples.length){S.samples.push(...j.samples);S.last=j.samples[j.samples.length-1].t;
   if(S.samples.length>S.history)S.samples.splice(0,S.samples.length-S.history)}
  const st=j.status;$('host').textContent=st.host+(st.method?` · via ${st.method}`:'');
  $('dot').style.background=css(st.connected?'--ok':'--bad');
  $('st').textContent=st.connected?'live':(st.error?'error: '+st.error:'connecting…');
  $('up').textContent=st.uptime||'';
  $('db').textContent=st.db?`· db ${st.db} (${st.db_rows.toLocaleString()} rows)`:'· db off';render();
 }catch(e){$('dot').style.background=css('--bad');$('st').textContent='web server unreachable'}
 setTimeout(poll,Math.max(1000,S.interval*1000));
}
for(const id of['cpu','mem','net']){const c=$(id);
 c.addEventListener('mousemove',e=>{const g=c._geo;if(!g)return;const x=e.offsetX,t=g.t0+(x-g.P.l)/g.pw*(g.t1-g.t0);
  let best=0,bd=Infinity;g.times.forEach((tt,i)=>{const dd=Math.abs(tt-t);if(dd<bd){bd=dd;best=i}});
  for(const k of['cpu','mem','net'])S.hover[k]=best;render()});
 c.addEventListener('mouseleave',()=>{S.hover={};render()})}
$('iface').onchange=e=>{S.iface=e.target.value;render()};
$('tbl').onclick=e=>{const tr=e.target.closest('tr');if(tr){S.iface=tr.dataset.i;render()}};
$('reset').onclick=async()=>{
 if(!confirm('Delete all collected history'+(S.db?' (including the SQLite database)':'')+'? This cannot be undone.'))return;
 const r=await fetch('/api/reset',{method:'POST',headers:{'X-UTR-Reset':'1'}});
 if(r.ok){S.samples=[];S.last=0;S.iface=null;render()}else alert('Reset failed: '+r.status)};
$('win').onchange=render;window.addEventListener('resize',render);
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
                try:
                    since = float(parse_qs(u.query).get("since", ["0"])[0])
                except ValueError:
                    since = 0.0
                self._send(200, json.dumps(collector.snapshot(since)), "application/json")
            elif u.path == "/api/export.csv":
                self._csv()
            else:
                self._send(404, "not found", "text/plain")
 
    return Handler
 
 
def main():
    ap = argparse.ArgumentParser(description="Graph a UniFi Travel Router's CPU/MEM/network via SSH.")
    ap.add_argument("host", nargs="?", help="UTR IP address / hostname")
    ap.add_argument("-u", "--user", default="ui", help="SSH user (default: ui)")
    ap.add_argument("-p", "--password", help="SSH password (else $UTR_PASSWORD, else prompt)")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("-i", "--interval", type=float, default=2.0, help="poll interval seconds (default 2)")
    ap.add_argument("--history", type=int, default=3600, help="samples kept in memory (default 3600)")
    ap.add_argument("--iface", action="append", help="only track this interface (repeatable)")
    ap.add_argument("--bind", default="127.0.0.1", help="web server bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="web server port (default 8080)")
    ap.add_argument("--db", help="SQLite file (default: utr-monitor-<host>.db in the current directory)")
    ap.add_argument("--no-db", action="store_true", help="don't persist samples to SQLite")
    ap.add_argument("--retention-days", type=float, default=30,
                    help="prune DB rows older than this many days (0 = keep forever; default 30)")
    ap.add_argument("--demo", action="store_true", help="generate fake data, no SSH")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
 
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    if not a.verbose:
        logging.getLogger("paramiko").setLevel(logging.WARNING)
 
    if a.demo:
        runner = DemoRunner()
    else:
        if not a.host:
            ap.error("host is required (or use --demo)")
        pw = a.password or os.environ.get("UTR_PASSWORD") or getpass.getpass(f"Password for {a.user}@{a.host}: ")
        runner = SSHRunner(a.host, a.user, pw, port=a.ssh_port)
 
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
    col = Collector(runner, max(0.5, a.interval), a.history, a.iface, store)
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
 
