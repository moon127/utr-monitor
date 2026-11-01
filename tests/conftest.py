"""Shared fixtures. The scripts have hyphenated names, so they're loaded by path."""
import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MON = _load("utr_monitor", "utr-monitor.py")
PROBE = _load("utr_probe", "utr-probe.py")


@pytest.fixture
def mon():
    return MON


@pytest.fixture
def probe():
    return PROBE


class FakeRunner:
    """Stands in for SSHRunner. `responses` maps a command (or a callable) to output."""

    host = "10.0.0.1"
    user = "ui"

    def __init__(self, responses=None, default=""):
        self.responses = responses or {}
        self.default = default
        self.calls = []
        self.closed = 0
        self.mode = "exec"
        self.password = "pw"

    def run(self, cmd):
        self.calls.append(cmd)
        out = self.responses.get(cmd, self.default)
        if isinstance(out, Exception):
            raise out
        return out(cmd) if callable(out) else out

    def close(self):
        self.closed += 1

    def connect(self):
        pass


@pytest.fixture
def fake_runner():
    return FakeRunner


@pytest.fixture
def keyring_stub(monkeypatch):
    """An in-memory stand-in for the `keyring` package."""
    kr = types.ModuleType("keyring")
    kr.store = {}
    kr.get_keyring = lambda: "stub"
    kr.get_password = lambda svc, user: kr.store.get((svc, user))

    def set_password(svc, user, pw):
        kr.store[(svc, user)] = pw

    def delete_password(svc, user):
        del kr.store[(svc, user)]  # KeyError when missing, like the real backends
    kr.set_password, kr.delete_password = set_password, delete_password
    monkeypatch.setitem(sys.modules, "keyring", kr)
    return kr


@pytest.fixture
def no_keyring(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)  # makes `import keyring` raise ImportError
