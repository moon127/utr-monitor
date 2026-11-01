"""HTTP handler: page, JSON API, CSV export and reset protection."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

NOW = 1_800_000_000.0


@pytest.fixture
def server(mon, fake_runner, tmp_path):
    def start(store=None):
        col = mon.Collector(fake_runner(), 2, 10, store=store)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), mon.make_handler(col))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return col, f"http://127.0.0.1:{srv.server_address[1]}"
    servers = []
    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def get(url, **kw):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, **kw), timeout=5) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def sample(t, net):
    return {"t": t, "cpu": 5.0, "mem_pct": 40.0, "mem_used_mb": None, "mem_total_mb": 200.0, "load1": 0.2, "net": net}


def test_page_and_api(mon, server):
    col, base = server()
    col.samples.extend([sample(NOW, {}), sample(NOW + 2, {"eth0": [1.0, 2.0]})])
    col.state = {"system": {"hostname": "Test-UTR"}}
    status, headers, body = get(base + "/")
    assert status == 200 and headers["Content-Type"].startswith("text/html") and "<title>UTR Monitor</title>" in body
    assert headers["Cache-Control"] == "no-store"
    data = json.loads(get(base + f"/api/data?since={NOW}&dsince=0&eseq=0")[2])
    assert [s["t"] for s in data["samples"]] == [NOW + 2] and data["state"]["system"]["hostname"] == "Test-UTR"
    assert data["interval"] == 2 and data["dinterval"] == 10.0
    data = json.loads(get(base + "/api/data?since=bogus&eseq=x")[2])      # bad cursors read as 0
    assert len(data["samples"]) == 2
    assert json.loads(get(base + "/api/state")[2]) == {"system": {"hostname": "Test-UTR"}}
    assert get(base + "/nope")[0] == 404


def test_csv_from_memory(mon, server):
    col, base = server()
    col.samples.extend([sample(NOW, {"eth0": [1.0, 2.0]}), sample(NOW + 2, {"wg0": [3.0, 4.0]})])
    status, headers, body = get(base + "/api/export.csv")
    lines = body.strip().split("\n")
    assert status == 200 and "attachment" in headers["Content-Disposition"]
    assert lines[0] == "time,cpu_pct,mem_pct,mem_used_mb,load1,eth0_rx_bps,eth0_tx_bps,wg0_rx_bps,wg0_tx_bps"
    assert lines[1].endswith(",5.0,40.0,,0.2,8,16,,")                     # bits/s; missing iface left blank
    assert lines[2].endswith(",,,24,32")


def test_csv_from_store_streams_in_chunks(mon, server, tmp_path):
    store = mon.Store(str(tmp_path / "w.db"))
    with store.lock:
        store.db.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?)",
                             [(NOW + i, 1.0, 2.0, 3.0, 4.0, 0.1, '{"eth0":[1,1]}') for i in range(5003)])
        store.db.commit()
    _, base = server(store)
    body = get(base + "/api/export.csv")[2]
    assert len(body.strip().split("\n")) == 5004
    store.close()


def test_reset_requires_header(mon, server):
    col, base = server()
    col.samples.append(sample(NOW, {}))
    assert get(base + "/api/reset", method="POST")[0] == 403              # e.g. a form post from another site
    assert len(col.samples) == 1
    status, _, body = get(base + "/api/reset", method="POST", headers={"X-UTR-Reset": "1"})
    assert status == 200 and json.loads(body) == {"ok": True} and not col.samples
    assert get(base + "/api/other", method="POST")[0] == 404
