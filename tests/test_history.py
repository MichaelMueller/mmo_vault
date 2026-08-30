"""Generations: kept without limit, deleted only by hand, restored forwards."""

from __future__ import annotations

import json

import pytest

from mmo_vault.server import db, storage
from mmo_vault.server.models import Generation

from .conftest import HEADERS, user_client


def vault_text(marker: str) -> str:
    return "\n".join([
        json.dumps({"type": "header", "format": "mmo-vault-v3", "salt": "AAAA", "iterations": 600000}),
        json.dumps({"type": "text", "iv": "AAAA", "data": marker}),
    ])


@pytest.fixture
def vault(admin):
    """A vault shared with the administrator, plus a held lock."""
    vault_id = admin.post("/api/vaults", json={"name": "Team-Vault"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "Admin", "permission": "readwrite"}]})
    token = admin.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
    return vault_id, token


def write(client, vault_id, text, etag, token):
    return client.put(f"/api/vaults/{vault_id}/content", content=text, headers={
        **HEADERS, "If-Match": f'"{etag}"', "X-Vault-Lock": token})


def test_every_save_is_kept(admin, vault):
    vault_id, token = vault
    etag = ""
    for marker in ["AAA", "BBB", "CCC"]:
        etag = write(admin, vault_id, vault_text(marker), etag, token).json()["etag"]
    body = admin.get(f"/api/vaults/{vault_id}/history").json()
    assert [g["seq"] for g in body["generations"]] == [3, 2, 1]
    assert body["generations"][0]["author"] == "Admin"
    assert admin.get("/api/vaults").json()[0]["generations"] == 3


def test_a_generation_can_be_read_back(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("ERSTE"), "", token)
    result = admin.get(f"/api/vaults/{vault_id}/history/1/content")
    assert result.status_code == 200
    assert result.text == vault_text("ERSTE")
    assert "attachment" in result.headers["content-disposition"]


def test_an_unknown_generation_is_a_404(admin, vault):
    vault_id, _ = vault
    assert admin.get(f"/api/vaults/{vault_id}/history/99/content").status_code == 404


def test_restoring_writes_a_new_generation(admin, vault):
    """Forwards, not backwards - the history stays gapless and the restore
    itself can be undone."""
    vault_id, token = vault
    etag = write(admin, vault_id, vault_text("ALT"), "", token).json()["etag"]
    write(admin, vault_id, vault_text("KAPUTT"), etag, token)
    result = admin.post(f"/api/vaults/{vault_id}/history/1/restore",
                        headers={**HEADERS, "X-Vault-Lock": token})
    assert result.status_code == 200, result.text
    assert result.json()["generation"] == 3
    assert admin.get(f"/api/vaults/{vault_id}/content").text == vault_text("ALT")
    generations = admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]
    assert [g["seq"] for g in generations] == [3, 2, 1]
    assert generations[0]["note"] == "restored from #1"


def test_restoring_needs_the_lock(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("ALT"), "", token)
    admin.request("DELETE", f"/api/vaults/{vault_id}/lock", headers={**HEADERS, "X-Vault-Lock": token})
    assert admin.post(f"/api/vaults/{vault_id}/history/1/restore", headers=HEADERS).status_code == 409


def test_write_permission_is_enough_to_restore(admin, vault, app):
    vault_id, token = vault
    write(admin, vault_id, vault_text("ALT"), "", token)
    admin.request("DELETE", f"/api/vaults/{vault_id}/lock", headers={**HEADERS, "X-Vault-Lock": token})
    with user_client(app, "kollege@example.test") as client:
        admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
            {"subject_type": "user", "subject": "Kollege", "permission": "readwrite"}]})
        own_token = client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
        assert client.post(f"/api/vaults/{vault_id}/history/1/restore",
                           headers={**HEADERS, "X-Vault-Lock": own_token}).status_code == 200


def test_read_only_may_not_restore(admin, vault, app):
    vault_id, token = vault
    write(admin, vault_id, vault_text("ALT"), "", token)
    with user_client(app, "kollege@example.test") as client:
        admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
            {"subject_type": "user", "subject": "Kollege", "permission": "read"}]})
        assert client.get(f"/api/vaults/{vault_id}/history").status_code == 200
        assert client.post(f"/api/vaults/{vault_id}/history/1/restore", headers=HEADERS).status_code == 403


def test_deleting_a_single_generation(admin, vault):
    vault_id, token = vault
    etag = write(admin, vault_id, vault_text("AAA"), "", token).json()["etag"]
    write(admin, vault_id, vault_text("BBB"), etag, token)
    assert admin.delete(f"/api/vaults/{vault_id}/history/1", headers=HEADERS).status_code == 200
    assert [g["seq"] for g in admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]] == [2]
    assert storage.read_generation(vault_id, 1) is None


def test_numbers_are_never_reused(admin, vault):
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
    assert admin.delete(f"/api/vaults/{vault_id}/history?before=3", headers=HEADERS).json()["removed"] == 2
    assert [g["seq"] for g in admin.get(f"/api/vaults/{vault_id}/history").json()["generations"]] == [3]


def test_deleting_the_history_keeps_the_current_file(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)
    assert admin.delete(f"/api/vaults/{vault_id}/history", headers=HEADERS).json()["removed"] == 1
    assert admin.get(f"/api/vaults/{vault_id}/history").json()["generations"] == []
    assert admin.get(f"/api/vaults/{vault_id}/content").text == vault_text("AAA")


def test_only_administrators_may_delete(admin, vault, app):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)
    with user_client(app, "kollege@example.test") as client:
        admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
            {"subject_type": "user", "subject": "Kollege", "permission": "readwrite"}]})
        assert client.delete(f"/api/vaults/{vault_id}/history/1", headers=HEADERS).status_code == 403
        assert client.delete(f"/api/vaults/{vault_id}/history", headers=HEADERS).status_code == 403


def test_the_size_is_reported_and_marked(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)
    body = admin.get(f"/api/vaults/{vault_id}/history").json()
    assert body["total_bytes"] == len(vault_text("AAA").encode())
    assert body["warn"] is False
    # The mark is a statement, not a limit - set through the settings now.
    admin.put("/api/settings", headers=HEADERS, json={"history_warn_bytes": 1})
    body = admin.get(f"/api/vaults/{vault_id}/history").json()
    assert body["warn"] is True
    assert len(body["generations"]) == 1


def test_deleting_the_vault_takes_the_history(admin, vault):
    vault_id, token = vault
    write(admin, vault_id, vault_text("AAA"), "", token)
    assert storage.history_dir(vault_id).exists()
    admin.delete(f"/api/vaults/{vault_id}", headers=HEADERS)
    assert not storage.vault_dir(vault_id).exists()
    db.init()
    with db.session_scope() as session:
        assert session.query(Generation).count() == 0
