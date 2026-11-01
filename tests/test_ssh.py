"""SSHRunner: exec channels, interactive-shell fallback and reconnects, against a fake paramiko client."""
import sys

import paramiko
import pytest


class FakeTransport:
    def __init__(self):
        self.active = True
        self.keepalive = None

    def is_active(self):
        return self.active

    def set_keepalive(self, n):
        self.keepalive = n


class FakeChannel:
    """Echoes the command like a terminal, then prints output, the marker and a prompt."""

    def __init__(self, output, banner="Welcome\r\n# "):
        self.output = output
        self.buf = banner.encode()
        self.closed = False
        self.exited = False

    def recv_ready(self):
        return bool(self.buf)

    def recv(self, n):
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def exit_status_ready(self):
        return self.exited

    def send(self, data):
        cmd = data.rstrip("\n")
        marker = cmd.rsplit("echo ", 1)[1].replace('"', "")
        self.buf += f"{cmd}\r\n{self.output}{marker}\r\n# ".encode()

    def close(self):
        raise OSError("already closed")       # close() errors are swallowed


class FakeStdout:
    def __init__(self, text):
        self.text = text

    def read(self):
        return self.text.encode()


class FakeClient:
    exec_result = "exec output\n"
    shell_output = "\x1b[1mline one\x1b[0m\r\nline two\r\n"

    def __init__(self):
        self.transport = FakeTransport()
        self.connected = None

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, host, **kw):
        self.connected = (host, kw)

    def get_transport(self):
        return self.transport

    def exec_command(self, cmd, timeout=None):
        if isinstance(self.exec_result, Exception):
            raise self.exec_result
        return None, FakeStdout(self.exec_result), None

    def invoke_shell(self, **kw):
        return FakeChannel(self.shell_output)

    def close(self):
        pass


@pytest.fixture
def client_cls(monkeypatch):
    cls = type("Client", (FakeClient,), {})
    monkeypatch.setattr(paramiko, "SSHClient", cls)
    return cls


@pytest.fixture
def fast_time(mon, monkeypatch):
    t = {"now": 1000.0}

    def now():
        t["now"] += 0.05
        return t["now"]
    monkeypatch.setattr(mon.time, "time", now)
    monkeypatch.setattr(mon.time, "sleep", lambda s: None)
    return t


def test_requires_paramiko(mon, monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", None)
    with pytest.raises(SystemExit):
        mon.SSHRunner("h", "u", "p")


def test_exec_mode(mon, client_cls):
    r = mon.SSHRunner("10.0.0.1", "ui", "pw", port=2222, timeout=5)
    assert r.run("uptime") == "exec output\n" and r.mode == "exec"
    host, kw = r.client.connected
    assert host == "10.0.0.1" and kw["port"] == 2222 and kw["look_for_keys"] is False
    assert r.client.transport.keepalive == 15
    client = r.client
    assert r.run("again") == "exec output\n" and r.client is client    # reuses a live session
    client.transport.active = False
    r.run("after drop")
    assert r.client is not client                                       # reconnected
    client_cls.exec_result = ""
    assert r.run("empty") == ""                                         # empty output is fine once in exec mode
    client_cls.exec_result = RuntimeError("channel refused")
    with pytest.raises(RuntimeError):
        r.run("fails")                                                  # errors surface once exec is known to work


@pytest.mark.parametrize("exec_result", ["", RuntimeError("exec not allowed")])
def test_falls_back_to_shell(mon, client_cls, fast_time, exec_result):
    client_cls.exec_result = exec_result
    r = mon.SSHRunner("10.0.0.1", "ui", "pw")
    assert r.run("cat /proc/stat") == "line one\nline two\n"
    assert r.mode == "shell"
    assert r.run("second") == "line one\nline two\n" and r._n == 2     # same shell, new marker
    r.close()
    assert r.chan is None and r.client is None


def test_shell_read_errors(mon, client_cls, fast_time):
    r = mon.SSHRunner("10.0.0.1", "ui", "pw")
    r.connect()
    r.chan = FakeChannel("", banner="")
    with pytest.raises(TimeoutError):
        r._shell_read_until("never", fast_time["now"] + 0.2)
    assert r._shell_read_until(None, fast_time["now"] + 0.2) == ""
    r.chan.exited = True
    with pytest.raises(ConnectionError):
        r._shell_read_until("never", fast_time["now"] + 10)
