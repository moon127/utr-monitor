"""Static checks on the dashboard page (the JavaScript isn't covered by Python coverage)."""
import json
import re
import shutil
import subprocess

import pytest

import helpers

HAS_NODE = bool(shutil.which("node"))
EVIL = "<img src=x onerror=alert(1)>"

# A tiny DOM so the page's own script can run under Node and we can inspect what it renders.
HARNESS = r"""
const fs = require('fs');
const data = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const realSetTimeout = setTimeout, els = {};
function el(id) {
  const ctx = new Proxy({}, {get: (t, k) => k in t ? t[k] : () => {}, set: (t, k, v) => (t[k] = v, true)});
  return {id, innerHTML: '', textContent: '', value: '', checked: false, dataset: {}, style: {},
    clientWidth: 400, clientHeight: 200, setAttribute() {}, addEventListener() {}, closest() { return null; },
    classList: {s: new Set(), toggle(c, on) { on ? this.s.add(c) : this.s.delete(c); }, contains(c) { return this.s.has(c); }},
    getContext() { return ctx; }};
}
global.document = {getElementById: id => els[id] || (els[id] = el(id)), documentElement: {dataset: {skin: 'classic'}}};
global.window = {devicePixelRatio: 1, addEventListener() {}};
global.getComputedStyle = () => ({getPropertyValue: () => '#000'});
global.localStorage = {getItem: () => null, setItem() {}};
global.confirm = () => false; global.alert = () => {};
global.setTimeout = () => {};
global.fetch = async () => ({ok: true, json: async () => data});
eval(fs.readFileSync(process.argv[2], 'utf8'));
realSetTimeout(() => {
  const out = {};
  for (const [id, e] of Object.entries(els)) out[id] = {html: e.innerHTML, text: e.textContent};
  console.log(JSON.stringify(out));
}, 50);
"""


def render(mon, tmp_path, payload):
    (tmp_path / "page.js").write_text(script_of(mon.PAGE))
    (tmp_path / "harness.js").write_text(HARNESS)
    (tmp_path / "data.json").write_text(json.dumps(payload))
    res = subprocess.run(["node", str(tmp_path / "harness.js"), str(tmp_path / "page.js"), str(tmp_path / "data.json")],
                         capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def hostile_payload(mon):
    """Detail data where every string another device controls is an HTML injection attempt."""
    now = 1_800_000_000.0
    out = helpers.detail_output(now)
    for name in ("TravelNet", "Phone", "Laptop", "Desktop", "Hotel", "Cafe", "Test Switch", "Home",
                 "Port 3", "WPA2-Personal", "U6-LR", "203.0.113.1:51820", "192.168.29.21"):
        out = out.replace(name, EVIL.replace('"', "'") + name)
    state, series, events = mon.parse_detail(out, now)
    events.append({"id": "z", "t": now, "category": EVIL, "event": "wifi_connected", "details": {"ssid": EVIL}})
    for i, e in enumerate(events):
        e["seq"] = i + 1
    sample = {"t": now, "cpu": 10.0, "mem_pct": 50.0, "mem_used_mb": 1.0, "mem_total_mb": 2.0, "load1": 0.1,
              "net": {"eth0": [1.0, 2.0], "ath1": [3.0, 4.0], EVIL: [1.0, 1.0]}}
    detail = dict(series, t=now, cpu_all=10.0, cpu_us=5.0, cpu_sy=3.0, cpu_si=2.0, vpn_bps=100.0,
                  wan_bps=200.0, nonvpn_bps=100.0, grp={"teleport": 1.0}, top=[[EVIL, "other", 1.0]])
    return {"status": {"connected": True, "error": None, "method": "proc", "uptime": "up 1 day", "host": "h",
                       "db": None, "db_rows": 0, "reset_gen": 0, "detail_ms": 5, "detail_error": None},
            "interval": 2, "dinterval": 10, "history": 3600, "samples": [sample, dict(sample, t=now + 2)],
            "details": [detail, dict(detail, t=now + 10)], "events": events, "state": state}


@pytest.mark.skipif(not HAS_NODE, reason="node not installed")
def test_router_strings_are_escaped(mon, tmp_path):
    # Network names, hostnames, event details etc. come from other people's devices
    rendered = render(mon, tmp_path, hostile_payload(mon))
    html = {k: v["html"] for k, v in rendered.items() if v["html"]}
    for key in ("clients", "wans", "vaps", "nbrs", "vpn", "events", "procs", "ifs", "iface", "t-wifi", "t-net", "t-vpn"):
        assert key in html, f"{key} wasn't rendered"
    leaks = {k: v for k, v in html.items() if "<img" in v}
    assert not leaks, f"unescaped HTML in: {sorted(leaks)}"
    assert "&lt;img" in html["clients"] and "&lt;img" in html["events"]


def script_of(page):
    return page[page.index("<script>\nconst S=") + len("<script>\n"):page.rindex("</script>")]


def test_no_external_resources(mon):
    # The page must work with no internet access (e.g. on the travel router's own LAN)
    assert not re.search(r"""(src|href)\s*=\s*["']?https?://""", mon.PAGE)
    assert "@import" not in mon.PAGE and "fetch('http" not in mon.PAGE


def test_every_referenced_element_exists(mon):
    ids = set(re.findall(r'id="([\w-]+)"', mon.PAGE))
    used = set(re.findall(r"\$\('([\w-]+)'\)", mon.PAGE)) | set(re.findall(r"getElementById\('([\w-]+)'\)", mon.PAGE))
    chart_ids = re.search(r"for\(const id of\[([^\]]+)\]\)", mon.PAGE).group(1)
    used |= set(re.findall(r"'([\w-]+)'", chart_ids))
    assert used - ids == set()


def test_persisted_preferences_use_safe_storage(mon):
    # localStorage is only for per-viewer preferences, always wrapped in try/catch
    js = mon.PAGE
    for m in re.finditer(r"localStorage\.\w+Item\([^)]*\)", js):
        before = js[max(0, m.start() - 80):m.start()]
        assert "try{" in before, m.group(0)


@pytest.mark.skipif(not HAS_NODE, reason="node not installed")
def test_javascript_parses(mon, tmp_path):
    f = tmp_path / "page.js"
    f.write_text(script_of(mon.PAGE))
    res = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
