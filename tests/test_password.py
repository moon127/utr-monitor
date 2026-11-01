"""Saved password (keychain via `keyring`) and the startup login check."""
import sys
import types

import paramiko
import pytest

KEY = ("utr-monitor", "ui@10.0.0.1")


def test_keyring_roundtrip(mon, keyring_stub):
    assert mon.stored_password("ui", "10.0.0.1") is None
    assert mon.save_password("ui", "10.0.0.1", "secret") and keyring_stub.store[KEY] == "secret"
    assert mon.stored_password("ui", "10.0.0.1") == "secret"
    assert mon.forget_password("ui", "10.0.0.1") is True
    assert mon.forget_password("ui", "10.0.0.1") is False          # nothing left to delete


def test_without_keyring(mon, no_keyring):
    assert mon._keyring() is None
    assert mon.stored_password("ui", "h") is None
    assert mon.save_password("ui", "h", "p") is False
    assert mon.forget_password("ui", "h") is False


def test_keyring_backend_errors(mon, monkeypatch, caplog):
    kr = types.ModuleType("keyring")
    kr.get_keyring = lambda: "broken backend"

    def boom(*a):
        raise RuntimeError("locked")
    kr.get_password = kr.set_password = kr.delete_password = boom
    monkeypatch.setitem(sys.modules, "keyring", kr)
    assert mon.stored_password("ui", "h") is None
    assert mon.save_password("ui", "h", "p") is False and "Couldn't save" in caplog.text
    no_backend = types.ModuleType("keyring")
    no_backend.get_keyring = boom
    monkeypatch.setitem(sys.modules, "keyring", no_backend)
    assert mon._keyring() is None


def test_resolve_password_order(mon, keyring_stub, monkeypatch):
    monkeypatch.setenv("UTR_PASSWORD", "from-env")
    keyring_stub.store[KEY] = "from-keychain"
    assert mon.resolve_password("ui", "10.0.0.1", "from-arg") == ("from-arg", "argument")
    assert mon.resolve_password("ui", "10.0.0.1") == ("from-env", "environment")
    monkeypatch.delenv("UTR_PASSWORD")
    assert mon.resolve_password("ui", "10.0.0.1") == ("from-keychain", "keychain")
    keyring_stub.store.clear()
    monkeypatch.setattr(mon.getpass, "getpass", lambda prompt: "typed")
    assert mon.resolve_password("ui", "10.0.0.1") == ("typed", "prompt")


class LoginRunner:
    host, user = "10.0.0.1", "ui"

    def __init__(self, password, good="right", error=None):
        self.password, self.good, self.error, self.attempts = password, good, error, 0

    def connect(self):
        self.attempts += 1
        if self.error:
            raise self.error
        if self.password != self.good:
            raise paramiko.AuthenticationException("bad password")


@pytest.fixture
def typed(mon, monkeypatch):
    answers = []
    monkeypatch.setattr(mon.getpass, "getpass", lambda prompt: answers.pop(0))
    return answers


def test_login_saves_typed_password(mon, keyring_stub, typed, caplog):
    caplog.set_level("INFO")
    mon.login(LoginRunner("right"), "prompt")
    assert keyring_stub.store[KEY] == "right" and "saved to the system keychain" in caplog.text


def test_login_no_save(mon, keyring_stub):
    mon.login(LoginRunner("right"), "prompt", save=False)
    assert KEY not in keyring_stub.store


def test_login_hint_without_keyring(mon, no_keyring, caplog):
    caplog.set_level("INFO")
    mon.login(LoginRunner("right"), "prompt")
    assert "pip install keyring" in caplog.text


def test_login_replaces_stale_saved_password(mon, keyring_stub, typed):
    keyring_stub.store[KEY] = "stale"
    typed += ["wrong", "right"]
    r = LoginRunner("stale")
    mon.login(r, "keychain")
    assert r.attempts == 3 and keyring_stub.store[KEY] == "right"


def test_login_rejects_argument_password(mon, keyring_stub):
    with pytest.raises(SystemExit, match="password rejected"):
        mon.login(LoginRunner("wrong"), "argument")


def test_login_gives_up_after_three_attempts(mon, keyring_stub, typed):
    typed += ["no", "nope"]
    with pytest.raises(SystemExit, match="after 3 attempts"):
        mon.login(LoginRunner("bad"), "prompt")


def test_login_unreachable_router_continues(mon, keyring_stub, caplog):
    mon.login(LoginRunner("right", error=OSError("no route to host")), "prompt")
    assert "will keep retrying" in caplog.text and KEY not in keyring_stub.store
