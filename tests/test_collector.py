"""Collector: fast poll, detail poll, CPU accounting, run loop, persistence."""
import pytest

import helpers

NOW = 1_800_000_000.0


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        self.t += 0.001
        return self.t


@pytest.fixture
def clock(mon, monkeypatch):
    c = Clock(NOW)
    monkeypatch.setattr(mon.time, "time", c)
    return c


def seq(*outputs):
    """Response that returns each output in turn, then repeats the last."""
    items = list(outputs)
    return lambda cmd: items.pop(0) if len(items) > 1 else items[0]


# ---- fast poll ---------------------------------------------------------------
def test_poll_once_proc(mon, fake_runner, clock):
    net2 = helpers.NET_DEV.replace("1000 0", "6000 0").replace("2000 0", "4000 0")
    stat2 = "cpu  200 0 100 1600 10 0 20 0 0 0\n"
    r = fake_runner({mon.PROC_CMD: seq(helpers.proc_output(), helpers.proc_output(),
                                       helpers.proc_output(stat=stat2, net=net2))})
    col = mon.Collector(r, 2, 10)
    first = col.poll_once()                       # also detects the method
    assert col.method == "proc" and first["cpu"] is None and first["net"] == {}
    assert first["mem_pct"] == 40.0 and first["load1"] == 0.5
    clock.t += 10
    second = col.poll_once()
    assert second["cpu"] == pytest.approx(100 * (1 - 800 / 950), abs=0.01)
    assert second["net"]["eth0"] == [pytest.approx(500, rel=0.01), pytest.approx(200, rel=0.01)]
    assert "lo" not in second["net"]
    assert col.status["uptime"].startswith("10:00:00 up")


def test_poll_once_counter_reset_and_filter(mon, fake_runner, clock):
    lower = helpers.NET_DEV.replace("1000 0", "10 0")
    r = fake_runner({mon.PROC_CMD: seq(helpers.proc_output(), helpers.proc_output(),
                                       helpers.proc_output(net=lower, uptime=""))})
    col = mon.Collector(r, 2, 10, iface_filter=["eth0", "lo"])
    col.poll_once()
    clock.t += 2
    s = col.poll_once()
    assert s["net"] == {"lo": [0.0, 0.0]}         # eth0 went backwards: skipped; filter keeps lo
    assert col.status["uptime"] == ""


def test_poll_once_top_fallback(mon, fake_runner, clock):
    top = ("Mem: 180000K used, 332000K free, 0K shrd, 8000K buff, 60000K cached\n"
           "CPU:   3% usr   2% sys   0% nic  94% idle\nLoad average: 0.12 0.2 0.1 1/9 1")
    out = f"{top}\n{helpers.SEP}\n{helpers.NET_DEV}{helpers.SEP}\n up 5 min"
    r = fake_runner({mon.PROC_CMD: "permission denied", mon.TOP_CMD: out})
    col = mon.Collector(r, 2, 10)
    s = col.poll_once()
    assert col.method == "top" and s["cpu"] == 6.0 and s["load1"] == 0.12 and s["mem_total_mb"] == 500.0


# ---- CPU accounting ----------------------------------------------------------
SNAP1_PROCS = [
    (1, "procd", 0, 50, 10, 1), (2, "kthreadd", 0, 0, 0, 1), (40, "kworker/u8:1", 2, 100, 0, 2),
    (900, "dropbear", 1, 5, 50, 50000), (2455, "teleport-client", 1, 200, 0, 900),
    (1566, "dnsmasq", 1, 10, 0, 900), (3629, "lcm-display", 1, 30, 400, 1000),
    (600, "sh", 3629, 1, 0, 99900), (601, "jq", 600, 1, 0, 99950),
    (700, "mcad", 1, 20, 5, 1200), (701, "sh", 700, 3, 0, 99000), (500, "sh", 900, 1, 0, 99990)]
SNAP2_PROCS = [
    (1, "procd", 0, 50, 10, 1), (2, "kthreadd", 0, 0, 0, 1), (40, "kworker/u8:1", 2, 180, 0, 2),
    (900, "dropbear", 1, 5, 80, 50000), (2455, "teleport-client", 1, 215, 0, 900),
    (1566, "dnsmasq", 1, 11, 0, 900), (3629, "lcm-display", 1, 32, 440, 1000),
    (603, "sh", 3629, 1, 0, 100990), (700, "mcad", 1, 24, 10, 1200),
    (502, "sh", 900, 2, 0, 100995), (801, "ulcmd", 1, 70, 0, 500)]
CMDS = {1566: "/usr/sbin/dnsmasq -C /tmp/teleport-client.d/dnsmasq.teleport.conf",
        600: "sh -c syswrapper.sh utr-api get-teleport-status",
        601: "jq -c {teleport: .} /tmp/teleport-client.d/connection-status.json",
        603: "sh -c syswrapper.sh utr-api get-teleport-status"}
NET2 = helpers.NET_DEV.replace("eth0: 1000 0", "eth0: 6000 0").replace("2000 0 0", "7000 0 0") \
    .replace("wg0: 500 0", "wg0: 1500 0").replace("600 0 0", "1600 0 0")


def test_cpu_accounting(mon, fake_runner):
    col = mon.Collector(fake_runner(), 2, 10)
    snap1 = helpers.proc_snapshot(500, 1000, [1000, 0, 500, 8000, 100, 0, 200, 0], SNAP1_PROCS, CMDS)
    snap2 = helpers.proc_snapshot(502, 1010, [1300, 0, 700, 11300, 100, 0, 400, 0], SNAP2_PROCS, CMDS, net=NET2)
    assert col._cpu_accounting(NOW, snap1, "eth0") == {}       # first snapshot is a baseline
    r = col._cpu_accounting(NOW + 10, snap2, "eth0")
    pct = lambda ticks: ticks / 4000 * 100
    assert r["cpu_all"] == pytest.approx(pct(700)) and r["cpu_us"] == pytest.approx(pct(300))
    assert r["cpu_sy"] == pytest.approx(pct(200)) and r["cpu_si"] == pytest.approx(pct(200))
    g = r["grp"]
    assert g["kernel"] == pytest.approx(pct(80), abs=0.01)
    assert g["teleport"] == pytest.approx(pct(16), abs=0.01)          # daemon + Teleport dnsmasq
    # lcm-display's reaped children (minus what was already counted) + the live status script
    assert g["teleport_poll"] == pytest.approx(pct(40), abs=0.01)
    # dropbear's reaped children (previous poll's shell, minus its counted tick) + this poll's shell
    assert g["monitor"] == pytest.approx(pct(31), abs=0.01)
    assert g["other"] == pytest.approx(pct(8), abs=0.01)
    assert g["unattributed"] == pytest.approx(pct(700 - 175), abs=0.01)
    assert r["top"][0][:2] == ["[kworker/u8:1]", "kernel"]
    labels = {t[0]: t[1] for t in r["top"]}
    assert labels["lcm-display (children)"] == "teleport_poll" and labels["dropbear (children)"] == "monitor"
    assert "ulcmd" not in labels                                     # first seen now: baseline only
    assert r["vpn_bps"] == 200.0 and r["wan_bps"] == 1000.0 and r["nonvpn_bps"] == 800.0
    # No CPU ticks elapsed: no result, and the baseline is refreshed
    assert col._cpu_accounting(NOW + 20, snap2, None) == {}
    assert col._cpu_accounting(NOW + 30, "garbage", None) == {}


def test_cpu_accounting_without_wan(mon, fake_runner):
    col = mon.Collector(fake_runner(), 2, 10)
    col._cpu_accounting(NOW, helpers.proc_snapshot(500, 1000, [0] * 8, SNAP1_PROCS), None)
    r = col._cpu_accounting(NOW + 10, helpers.proc_snapshot(502, 1010, [100, 0, 0, 300, 0, 0, 0, 0], SNAP2_PROCS), None)
    assert r["wan_bps"] is None and r["nonvpn_bps"] is None


# ---- detail poll -------------------------------------------------------------
def detail_with(mon, now, wired_tx, phone_tx, cpu, procs, shell, uptime, extra_wired=False):
    m = helpers.mca(now)
    m["vap_table"][0]["sta_table"][0]["tx_bytes"] = phone_tx
    net = helpers.NET_DEV + f"  eth1: 100 0 0 0 0 0 0 0 {wired_tx} 0 0 0 0 0 0 0\n"
    out = helpers.detail_output(now, mca_data=m, extra_proc=helpers.proc_snapshot(shell, uptime, cpu, procs, CMDS, net=net))
    if extra_wired:
        out = out.replace("192.168.29.60 0x1 0x2", "192.168.29.65 0x1 0x2 aa:00:00:00:00:0c * br-lan\n192.168.29.60 0x1 0x2")
        out = out.replace("  2\t", "  1\taa:00:00:00:00:0c\tno\t\t   1.00\n  2\t")
    return out


def test_poll_detail(mon, fake_runner, clock, tmp_path):
    store = mon.Store(str(tmp_path / "d.db"))
    out1 = detail_with(mon, NOW, 1000, 5000, [1000, 0, 500, 8000, 100, 0, 200, 0], SNAP1_PROCS, 500, 1000)
    out2 = detail_with(mon, NOW + 10, 11000, 15000, [1300, 0, 700, 11300, 100, 0, 400, 0], SNAP2_PROCS, 502, 1010)
    r = fake_runner({mon.DETAIL_CMD: seq(out1, out2)})
    col = mon.Collector(r, 2, 10, store=store)
    state = col.poll_detail()
    assert state["system"]["hostname"] == "Test-UTR" and len(col.events) == 4
    assert [e["seq"] for e in col.events] == [1, 2, 3, 4]
    clock.t += 10
    state = col.poll_detail()
    assert len(col.events) == 4                          # same log lines aren't added twice
    c = {x["mac"]: x for x in state["clients"]}
    assert c[helpers.PHONE]["down_bps"] == pytest.approx(1000, rel=0.01)
    wired = c[helpers.WIRED]
    assert wired["tx_bytes"] == 11000 and wired["down_bps"] == pytest.approx(1000, rel=0.01)
    assert "shared" not in wired and "mac_key" not in wired
    assert col.details[-1]["grp"]["kernel"] > 0
    assert col.status["detail_error"] is None and col.status["detail_ms"] is not None
    assert len(store.recent_details(10)) == 2 and len(store.recent_events(10)) == 4
    store.close()


def test_poll_detail_shared_port_and_accounting_failure(mon, fake_runner, clock, monkeypatch):
    out = detail_with(mon, NOW, 1000, 5000, [0] * 8, SNAP1_PROCS, 500, 1000, extra_wired=True)
    col = mon.Collector(fake_runner({mon.DETAIL_CMD: out}), 2, 10)
    monkeypatch.setattr(col, "_cpu_accounting", lambda *a: 1 / 0)
    col.seen = {str(i) for i in range(20001)}
    state = col.poll_detail()                             # accounting error is logged, not raised
    wired = [x for x in state["clients"] if x["wired"]]
    assert len(wired) == 2 and all(x["shared"] == 2 for x in wired)
    assert len(col.seen) < 20001                          # the seen-set is trimmed


# ---- run loop, reset, snapshot, store preload ---------------------------------
class Stop(Exception):
    pass


def test_run_loop(mon, fake_runner, monkeypatch, tmp_path, caplog):
    calls = {"proc": 0}

    def proc(cmd):
        calls["proc"] += 1
        if calls["proc"] == 4:
            raise ConnectionError("dropped")
        return helpers.proc_output()
    r = fake_runner({mon.PROC_CMD: proc, mon.DETAIL_CMD: RuntimeError("mca-dump failed")})
    store = mon.Store(str(tmp_path / "run.db"))
    col = mon.Collector(r, 0.01, 10, store=store, detail_interval=0.001)
    monkeypatch.setattr(store, "add", lambda s: 1 / 0)   # a DB write failure is logged, not fatal
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) >= 4:
            raise Stop
    monkeypatch.setattr(mon.time, "sleep", fake_sleep)
    with pytest.raises(Stop):
        col.run()
    assert len(col.samples) == 1                          # first poll only primes the counters
    assert col.status["detail_error"] == "mca-dump failed"
    assert "Poll failed: dropped" in caplog.text and "DB write failed" in caplog.text
    assert r.closed == 1 and 2 in sleeps                  # closed, backed off, then reconnected
    assert col.status["connected"] is True and col.status["error"] is None
    store.close()


def test_reset_snapshot_and_preload(mon, fake_runner, tmp_path):
    store = mon.Store(str(tmp_path / "p.db"))
    store.add({"t": NOW, "cpu": 1.0, "mem_pct": 1.0, "mem_used_mb": 1.0, "mem_total_mb": 2.0, "load1": 0.1, "net": {}})
    store.add_detail({"t": NOW, "ncl": 1})
    store.add_events([{"id": "x", "t": NOW, "category": "vpn", "event": "vpn_on", "details": {}}])
    col = mon.Collector(fake_runner(), 2, 10, store=store)
    assert len(col.samples) == 1 and len(col.details) == 1 and col.events[0]["seq"] == 1 and "x" in col.seen
    snap = col.snapshot()
    assert snap["status"]["db_rows"] == 1 and len(snap["samples"]) == 1 and len(snap["events"]) == 1
    assert col.snapshot(NOW, NOW, 1)["samples"] == [] and col.snapshot(NOW, NOW, 1)["events"] == []
    col.reset()
    assert not col.samples and not col.details and not col.events and "x" in col.seen
    assert col.status["reset_gen"] == 1 and store.count == 0
    store.close()
    nodb = mon.Collector(fake_runner(), 2, 10)
    nodb.reset()
    assert nodb.snapshot()["status"]["db_rows"] == 0


# ---- demo runner -------------------------------------------------------------
def test_demo_runner_end_to_end(mon, clock):
    demo = mon.DemoRunner()
    col = mon.Collector(demo, 1, 100)
    for _ in range(3):
        col.poll_once()
        clock.t += 5
    clock.t += 700                                         # crosses two simulated VPN reconnects
    for _ in range(3):
        col.poll_detail()
        demo.run(mon.PROC_CMD)
        clock.t += 10
    state = col.state
    assert state["system"]["hostname"] == "Demo-UTR" and state["vpn"]["teleport"]["state"] == "CONNECTED"
    assert {c["name"] for c in state["clients"]} >= {"Laptop", "Phone", "Tablet"}
    assert any(e["event"] == "vpn_off" for e in col.events)
    assert col.details[-1]["grp"]["teleport"] > 0 and col.details[-1]["vpn_bps"] > 0
    assert col.samples[-1]["cpu"] is not None if col.samples else True
    demo.close()
