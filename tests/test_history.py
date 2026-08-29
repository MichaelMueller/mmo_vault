"""Generations: kept without limit, deleted only by hand, restored forwards."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import db, storage
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config
from mmo_vault.server.models import Generation

from .authenticator import SoftAuthenticator

ORIGIN = "https://vault.example"
PASSWORD = "einSicheresBootstrapPasswort"
HEADERS = {"X-Vault-Request": "1"}


def vault_text(marker: str) -> str:
    return "\n".join([
        json.dumps({"type": "header", "format": "mmo-vault-v3",
                    "salt": "AAAA", "iterations": 600000}),
        json.dumps({"type": "text", "iv": "AAAA", "data": marker}),
    ])


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


def sign_in(config, name: str, password: str) -> TestClient:
    client = TestClient(create_app(config), base_url=ORIGIN)
    client.__enter__()
    client.post("/auth/login", json={"name": name, "password": password}, headers=HEADERS)
    started = client.post("/auth/passkey/register/options", headers=HEADERS).json()
    client.post("/auth/passkey/register/verify", json={
        "challenge_id": started["challenge_id"],
        "credential": SoftAuthenticator().create(started["options"], ORIGIN),
    }, headers=HEADERS)
    return client


@pytest.fixture
def admin(config):
    client = sign_in(config, "admin", PASSWORD)
    yield client
    client.__exit__(None, None, None)


@pytest.fixture
def vault(admin):
    """A vault shared with the administrator, plus a held lock."""
    vault_id = admin.post("/api/vaults", json={"name": "Team-Vault"},
                          headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "admin", "permission": "readwrite"}]})
    token = admin.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
    return vault_id, token


def write(client, vault_id, text, etag, token):
    return client.put(f"/api/vaults/{vault_id}/content", content=text, headers={
        **HEADERS, "If-Match": f'"{etag}"', "X-Vault-Lock": token})


# ----------------------------------------------------------------- gathering


def test_every_save_is_kept(admin, vault):
    vault_id, token = vault
    etag = ""
    for marker in ["AAA", "BBB", "CCC"]:
        etag = write(admin, vault_id, vault_text(marker), etag, token).json()["etag"]

    body = admin.get(f"/api/vaults/{vault_id}/history").json()
    assert [g["seq"] for g in body["generations"]] == [3, 2, 1]
    assert body["generations"][0]["author"] == "admin"
    assert body["total_bytes"] > 0
    # Nothing expires: three saves, three generations.
    assert admin.get("/api/vaults").json()[0]["generations"] == 3


def test_a_generation_can_be_read_back(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("ERSTE"), "", token)

    result = admin.get(f"/api/vaults/{vault_id}/history/1/content")
    assert result.status_code == 200
    assert result.text == vault_text("ERSTE")
    # Offered as a download - the most convenient path to an off-site backup.
    assert "attachment" in result.headers["content-disposition"]


def test_an_unknown_generation_is_a_404(admin, vault):
    vault_id, _ = vault
    assert admin.get(f"/api/vaults/{vault_id}/history/99/content").status_code == 404


# ---------------------------------------------------------------- restoring


def test_restoring_writes_a_new_generation(admin, vault):
    """Forwards, not backwards.

    Rewinding would leave a gap in the history and make the restore itself
    irreversible - exactly when someone is already in trouble.
    """
    vault_id, token = vault
    etag = write(admin, vault_id, vault_text("ALT"), "", token).json()["etag"]
    write(admin, vault_id, vault_text("KAPUTT"), etag, token)

    result = admin.post(f"/api/vaults/{vault_id}/history/1/restore",
                        headers={**HEADERS, "X-Vault-Lock": token})
    assert result.status_code == 200, result.text
    assert result.json()["generation"] == 3

    assert admin.get(f"/api/vaults/{vault_id}/content").text == vault_text("ALT")
    generations = admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]
    # The broken state is still there - the restore can be undone.
    assert [g["seq"] for g in generations] == [3, 2, 1]
    assert generations[0]["note"] == "restored from #1"


def test_restoring_needs_the_lock(admin, vault):
    """Replacing the content while somebody is editing would be the one case
    the ETag cannot catch - so the lock has to be held."""
    vault_id, token = vault
    write(admin, vault_id, vault_text("ALT"), "", token)
    admin.request("DELETE", f"/api/vaults/{vault_id}/lock",
                  headers={**HEADERS, "X-Vault-Lock": token})

    result = admin.post(f"/api/vaults/{vault_id}/history/1/restore", headers=HEADERS)
    assert result.status_code == 409


def test_write_permission_is_enough_to_restore(admin, vault, config):
    """Whoever may write could produce the same result by hand; restoring only
    makes it possible at all."""
    vault_id, token = vault
    write(admin, vault_id, vault_text("ALT"), "", token)
    admin.request("DELETE", f"/api/vaults/{vault_id}/lock",
                  headers={**HEADERS, "X-Vault-Lock": token})

    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "kollege", "permission": "readwrite"}]})

    with sign_in(config, "kollege", created["one_time_password"]) as client:
        own_token = client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
        result = client.post(f"/api/vaults/{vault_id}/history/1/restore",
                             headers={**HEADERS, "X-Vault-Lock": own_token})
        assert result.status_code == 200


def test_read_only_may_not_restore(admin, vault, config):
    vault_id, token = vault
    write(admin, vault_id, vault_text("ALT"), "", token)
    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "kollege", "permission": "read"}]})

    with sign_in(config, "kollege", created["one_time_password"]) as client:
        # Reading the history is fine, changing it is not.
        assert client.get(f"/api/vaults/{vault_id}/history").status_code == 200
        assert client.post(f"/api/vaults/{vault_id}/history/1/restore",
                           headers=HEADERS).status_code == 403


# ----------------------------------------------------------------- deleting


def test_deleting_a_single_generation(admin, vault, config):
    vault_id, token = vault
    etag = write(admin, vault_id, vault_text("AAA"), "", token).json()["etag"]
    write(admin, vault_id, vault_text("BBB"), etag, token)

    assert admin.delete(f"/api/vaults/{vault_id}/history/1", headers=HEADERS).status_code == 200
    remaining = admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]
    assert [g["seq"] for g in remaining] == [2]
    # The file is gone too, not just the record.
    assert storage.read_generation(vault_id, 1) is None


def test_numbers_are_never_reused(admin, vault):
    """A number that came back would make two different states look alike."""
    vault_id, token = vault
    etag = write(admin, vault_id, vault_text("AAA"), "", token).json()["etag"]
    admin.delete(f"/api/vaults/{vault_id}/history/1", headers=HEADERS)
    write(admin, vault_id, vault_text("BBB"), etag, token)

    assert [g["seq"] for g in admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]] == [2]


def test_deleting_everything_before_a_number(admin, vault):
    vault_id, token = vault
    etag = ""
    for marker in ["AAA", "BBB", "CCC"]:
        etag = write(admin, vault_id, vault_text(marker), etag, token).json()["etag"]

    result = admin.delete(f"/api/vaults/{vault_id}/history?before=3", headers=HEADERS)
    assert result.json()["removed"] == 2
    assert [g["seq"] for g in admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]] == [3]


def test_deleting_the_history_keeps_the_current_file(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)

    assert admin.delete(f"/api/vaults/{vault_id}/history", headers=HEADERS).json()["removed"] == 1
    assert admin.get(f"/api/vaults/{vault_id}/history").json()["generations"] == []
    # What is in use stays untouched.
    assert admin.get(f"/api/vaults/{vault_id}/content").text == vault_text("AAA")


def test_only_administrators_may_delete(admin, vault, config):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)
    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "kollege", "permission": "readwrite"}]})

    with sign_in(config, "kollege", created["one_time_password"]) as client:
        assert client.delete(f"/api/vaults/{vault_id}/history/1", headers=HEADERS).status_code == 403
        assert client.delete(f"/api/vaults/{vault_id}/history", headers=HEADERS).status_code == 403


def test_the_size_is_reported_and_marked(admin, vault, config):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)

    body = admin.get(f"/api/vaults/{vault_id}/history").json()
    assert body["total_bytes"] == len(vault_text("AAA").encode())
    assert body["warn"] is False

    # Nothing is deleted because of it - the mark is a statement, not a limit.
    config.vault.history_warn_bytes = 1
    assert admin.get(f"/api/vaults/{vault_id}/history").json()["warn"] is True
    assert len(admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]) == 1


def test_deleting_the_vault_takes_the_history(admin, vault, config):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)
    assert storage.history_dir(vault_id).exists()

    admin.delete(f"/api/vaults/{vault_id}", headers=HEADERS)
    assert not storage.vault_dir(vault_id).exists()

    db.init(config)
    with db.session_scope() as session:
        assert session.query(Generation).count() == 0
