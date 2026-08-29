"""Delivering the vault application: two changes, and no more.

What makes the whole arrangement defensible is that the file on disk stays the
one that also works offline. These tests hold that line.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import injection, storage
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config

from .authenticator import SoftAuthenticator

ORIGIN = "https://vault.example"
PASSWORD = "einSicheresBootstrapPasswort"
HEADERS = {"X-Vault-Request": "1"}


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    monkeypatch.setattr("mmo_vault.server.cli.VAR_DIR", tmp_path)
    monkeypatch.setattr(storage, "VAULTS_DIR", tmp_path / "vaults")
    assert main([
        "--config", str(path), "setup", "--non-interactive",
        "--database-url", f"sqlite:///{tmp_path / 'test.db'}",
        "--admin-name", "admin", "--admin-password", PASSWORD,
        "--rp-id", "vault.example", "--origin", ORIGIN,
    ]) == 0
    return Config.load(path)


@pytest.fixture
def client(config):
    with TestClient(create_app(config), base_url=ORIGIN) as test_client:
        test_client.post("/auth/login", json={"name": "admin", "password": PASSWORD},
                         headers=HEADERS)
        started = test_client.post("/auth/passkey/register/options", headers=HEADERS).json()
        test_client.post("/auth/passkey/register/verify", json={
            "challenge_id": started["challenge_id"],
            "credential": SoftAuthenticator().create(started["options"], ORIGIN),
        }, headers=HEADERS)
        yield test_client


def test_the_file_on_disk_is_untouched():
    """The point of the whole design.

    Whoever downloads the file gets one whose policy forbids every connection,
    and which contains no URL and no fetch call of its own.
    """
    original = injection.APP_PATH.read_text(encoding="utf-8")
    assert "connect-src 'none'" in original
    assert "window.mmoVaultServer =" not in original
    injection.render()
    assert injection.APP_PATH.read_text(encoding="utf-8") == original


def test_exactly_two_changes():
    original = injection.APP_PATH.read_text(encoding="utf-8")
    served = injection.render().html

    # 1. The policy is widened by exactly one word.
    assert "connect-src 'self'" in served
    assert "connect-src 'none'" not in served
    # 2. The adapter is added, inline - an external script would be blocked by
    #    script-src 'unsafe-inline', which is all the application allows.
    assert "window.mmoVaultServer" in served
    assert "<script src=" not in served.replace(original, "")

    # And nothing else: removing the addition and undoing the word gives the
    # original back.
    undone = served.replace(injection.render().script, "").replace(
        "<script>\n\n</script>\n", "").replace("connect-src 'self'", "connect-src 'none'")
    assert undone == original


def test_a_changed_application_file_is_noticed(monkeypatch, tmp_path):
    """Better a loud failure than an application served without its adapter.

    Without the check the vault list would simply stay empty, and nothing would
    say why.
    """
    broken = tmp_path / "broken.html"
    broken.write_text("<html><body>nothing here</body></html>", encoding="utf-8")
    monkeypatch.setattr(injection, "APP_PATH", broken)
    monkeypatch.setattr(injection, "_cache", None)
    with pytest.raises(injection.InjectionFailed):
        injection.render()


def test_the_adapter_comes_before_the_application(client):
    """Order decides whether any of this works at all.

    The application asks for window.mmoVaultServer while it starts up. An
    adapter added at the end of the document registers itself after that
    question has already been answered with no - and the vault list stays empty
    without a single error to point at.
    """
    served = client.get("/").text
    assert served.index("window.mmoVaultServer") < served.index("MIN_FILE_ITERATIONS")


def test_the_application_is_served_at_the_root(client):
    result = client.get("/")
    assert result.status_code == 200
    assert "MMO VAULT" in result.text
    assert "window.mmoVaultServer" in result.text
    # A cached copy would point at a session that no longer exists.
    assert result.headers["cache-control"] == "no-store"


def test_the_injection_is_public_reading(client):
    """It has to stay checkable - that is what the argument rests on."""
    result = client.get("/api/injection")
    assert result.status_code == 200
    assert "window.mmoVaultServer" in result.text
    assert result.text == injection.render().script


def test_without_a_session_there_is_no_application(config):
    with TestClient(create_app(config), base_url=ORIGIN) as anonymous:
        result = anonymous.get("/", follow_redirects=False)
        assert result.headers["location"] == "/login"


def test_an_enrolment_session_gets_no_application(config):
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/login", json={"name": "admin", "password": PASSWORD}, headers=HEADERS)
        # Its one destination is the registration, not the vault.
        assert client.get("/", follow_redirects=False).headers["location"] == "/enroll"


def test_the_beacon_releases_a_lock(client):
    """navigator.sendBeacon can only send a plain POST.

    No custom headers - so neither the CSRF header nor the regular release
    endpoint work from there. The token is the proof instead.
    """
    vault_id = client.post("/api/vaults", json={"name": "V"}, headers=HEADERS).json()["id"]
    client.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "admin", "permission": "readwrite"}]})
    token = client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]

    # Without the CSRF header, as a beacon really sends it.
    result = client.post(f"/api/vaults/{vault_id}/lock/release-beacon?token={token}")
    assert result.status_code == 200
    assert result.json()["released"] is True
    assert client.get(f"/api/vaults/{vault_id}/lock").json()["locked_by"] is None

    # A wrong token releases nothing.
    client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS)
    assert client.post(
        f"/api/vaults/{vault_id}/lock/release-beacon?token=falsch"
    ).json()["released"] is False
