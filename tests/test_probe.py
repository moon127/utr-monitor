"""utr-probe.py: redaction and report writing."""
import sys

import pytest


def test_redact(probe):
    text = "\n".join([
        "wireless.wifinet0.key='hunter2'",
        "  private key: (hidden)",
        "    option password 'abc'",
        "mesh.psk=secret",
        "PersistentKeepalive = 25",          # contains "key" inside a longer word: still treated as sensitive
        "plain line",
        "$ cat /etc/config/wireless",        # command lines are never redacted
        "== token-file",
    ])
    out = probe.redact(text).split("\n")
    assert out[0] == "wireless.wifinet0.key= <redacted>"
    assert out[1] == "  private  <redacted>"
    assert out[2] == "    option password  <redacted>"
    assert out[3] == "mesh.psk= <redacted>"
    assert out[5] == "plain line" and out[6] == "$ cat /etc/config/wireless" and out[7] == "== token-file"


class ProbeRunner:
    mode = "exec"

    def __init__(self, host, user, pw, port=22, timeout=10):
        self.args, self.closed, self.calls = (host, user, pw, port), 0, []

    def run(self, cmd):
        self.calls.append(cmd)
        if cmd.startswith("wg show"):
            raise ConnectionError("channel closed")
        if cmd.startswith("logread"):
            return "\n".join(f"line {i}" for i in range(1600))
        if cmd.startswith("ls -la /etc/wireguard"):
            return ""
        return "option key 'xyz'\nok\n"

    def close(self):
        self.closed += 1


@pytest.fixture
def run_probe(probe, monkeypatch, tmp_path):
    made = []

    def factory(*a, **kw):
        made.append(ProbeRunner(*a, **kw))
        return made[-1]
    monkeypatch.setattr(probe.mon, "SSHRunner", factory)
    monkeypatch.setenv("UTR_PASSWORD", "pw")

    def run(*args):
        out = tmp_path / "report.txt"
        monkeypatch.setattr(sys, "argv", ["utr-probe.py", "10.0.0.1", "-o", str(out), *args])
        probe.main()
        return out.read_text(), made[-1]
    return run


def test_report(run_probe, capsys):
    report, runner = run_probe("-s", "vpn, logs")
    assert runner.args == ("10.0.0.1", "ui", "pw", 22)
    assert "########## VPN ##########" in report and "########## Logs ##########" in report
    assert "########## System ##########" not in report
    assert "# ssh mode: exec; commands ok:" in report and "failed: 1" in report
    assert "!! failed: channel closed" in report and runner.closed == 2   # reconnect after failure, then done
    assert "option key  <redacted>" in report and "xyz" not in report
    assert "(no output)" in report
    assert "... (100 more lines truncated)" in report
    assert "ERR wg show" in capsys.readouterr().out


def test_report_all_sections(run_probe, probe):
    report, runner = run_probe()
    assert len(runner.calls) == sum(len(c) for _, c in probe.PROBES)
