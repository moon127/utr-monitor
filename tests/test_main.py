"""Command-line entry point of utr-monitor.py."""
import json
import sys

import pytest


class FakeServer:
    instances = []

    def __init__(self, addr, handler):
        self.addr, self.closed = addr, False
        FakeServer.instances.append(self)

    def serve_forever(self):
        raise KeyboardInterrupt        # what Ctrl+C does

    def server_close(self):
        self.closed = True


class FakeSSH:
    def __init__(self, host, user, pw, port=22, timeout=10):
        self.host, self.user, self.password, self.port = host, user, pw, port
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def run_main(mon, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mon, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(mon.Collector, "start", lambda self: setattr(self, "started", True))
    monkeypatch.setattr(mon, "SSHRunner", FakeSSH)
    logins = []
    monkeypatch.setattr(mon, "login", lambda runner, source, save=True: logins.append((runner, source, save)))
    FakeServer.instances.clear()

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["utr-monitor.py", *args])
        mon.main()
        return logins
    return run


def test_demo_mode_serves_without_db(run_main, tmp_path, caplog):
    caplog.set_level("INFO")
    run_main("--demo", "--port", "0", "--bind", "0.0.0.0", "-v")
    assert FakeServer.instances[0].closed and "Shutting down" in caplog.text
    assert "Web UI:  http://127.0.0.1:0/" in caplog.text
    assert not list(tmp_path.glob("*.db"))                  # demo data stays out of any database


def test_demo_with_explicit_db(run_main, tmp_path):
    run_main("--demo", "--db", "demo.db", "--detail-interval", "0", "--retention-days", "0")
    assert (tmp_path / "demo.db").exists()


def test_router_mode_default_db_name(run_main, tmp_path, monkeypatch, mon):
    monkeypatch.setattr(mon, "resolve_password", lambda u, h, p=None: ("pw", "keychain"))
    logins = run_main("10.0.0.1", "--no-save-password", "--ssh-port", "2222", "--detail-interval", "1")
    runner, source, save = logins[0]
    assert (runner.host, runner.port, source, save) == ("10.0.0.1", 2222, "keychain", False)
    assert runner.closed and (tmp_path / "utr-monitor-10.0.0.1.db").exists()


def test_router_mode_no_db(run_main, tmp_path, monkeypatch, mon):
    monkeypatch.setattr(mon, "resolve_password", lambda u, h, p=None: (p, "argument"))
    logins = run_main("router.local", "-p", "secret", "--no-db")
    assert logins[0][0].password == "secret" and not list(tmp_path.glob("*.db"))


def test_host_required(run_main):
    with pytest.raises(SystemExit):
        run_main()


def test_forget_password(run_main, keyring_stub, capsys):
    keyring_stub.store[("utr-monitor", "ui@10.0.0.1")] = "x"
    run_main("10.0.0.1", "--forget-password")
    assert "Removed the saved password for ui@10.0.0.1" in capsys.readouterr().out
    run_main("10.0.0.1", "--forget-password")
    assert capsys.readouterr().out.strip() == "No saved password for ui@10.0.0.1"


def test_forget_password_without_keyring(run_main, no_keyring, capsys):
    run_main("10.0.0.1", "--forget-password")
    assert "keyring package isn't installed" in capsys.readouterr().out


def test_once_prints_state(run_main, capsys):
    run_main("--demo", "--once")
    state = json.loads(capsys.readouterr().out)
    assert state["system"]["hostname"] == "Demo-UTR" and state["_events"] and "_detail_ms" in state
