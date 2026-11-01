"""SQLite persistence."""
import time


def sample(t, cpu=10.0, net=None):
    return {"t": t, "cpu": cpu, "mem_pct": 50.0, "mem_used_mb": 100.0, "mem_total_mb": 200.0,
            "load1": 0.5, "net": net or {"eth0": [1.0, 2.0]}}


def test_roundtrip_and_reset(mon, tmp_path):
    db = tmp_path / "t.db"
    s = mon.Store(str(db))
    now = time.time()
    for i in range(5):
        s.add(sample(now + i))
    s.add_detail({"t": now, "lat": {"eth0": 4.0}, "ncl": 2})
    s.add_events([{"id": "a", "t": now, "category": "vpn", "event": "vpn_on", "details": {"new": "x"}}])
    s.add_events([{"id": "a", "t": now, "category": "vpn", "event": "vpn_on", "details": {}}])  # duplicate ignored
    s.add_events([])
    assert s.count == 5
    assert [r["t"] for r in s.recent(3)] == [now + 2, now + 3, now + 4]
    assert s.recent(1)[0]["net"] == {"eth0": [1.0, 2.0]}
    assert s.recent_details(10) == [{"t": now, "lat": {"eth0": 4.0}, "ncl": 2}]
    assert s.recent_events(10)[0]["details"] == {"new": "x"} and len(s.recent_events(10)) == 1
    assert len(list(s.iter_all())) == 5
    s.close()

    s = mon.Store(str(db))           # reopening keeps everything
    assert s.count == 5
    s.reset()
    assert s.count == 0 and s.recent(10) == [] and s.recent_details(10) == [] and s.recent_events(10) == []
    s.close()


def test_retention_prunes_old_rows(mon, tmp_path):
    s = mon.Store(str(tmp_path / "r.db"), retention_days=1)
    old, now = time.time() - 3 * 86400, time.time()
    s.add(sample(old))
    s.add_detail({"t": old, "ncl": 1})
    s.add_events([{"id": "old", "t": old, "category": "c", "event": "e", "details": {}}])
    s._last_prune = 0                 # force the periodic prune on the next write
    s.add(sample(now))
    assert s.count == 1 and [r["t"] for r in s.recent(10)] == [now]
    assert s.recent_details(10) == [] and s.recent_events(10) == []
    s.close()
    # Pruning also happens when the file is opened
    s = mon.Store(str(tmp_path / "r.db"), retention_days=0.5)
    assert s.count == 1
    s.close()
