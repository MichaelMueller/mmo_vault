"""Vaults: sharing, writing, ETag and the lock model."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from mmo_vault.server import db, storage
from mmo_vault.server.models import VaultLock, utcnow

from .conftest import HEADERS, user_client

# A minimally valid vault file - enough for the structural check, and
# meaningless without the master password, exactly as in real life.
VAULT_V2 = "\n".join([
    json.dumps({"type": "header", "format": "mmo-vault-v2", "salt": "AAAA", "iterations": 600000}),
    json.dumps({"type": "text", "iv": "AAAA", "data": "BBBB"}),
])
VAULT_V3 = "\n".join([
    json.dumps({"type": "header", "format": "mmo-vault-v3", "salt": "AAAA", "iterations": 600000}),
    json.dumps({"type": "text", "iv": "AAAA", "data": "CCCC"}),
    json.dumps({"type": "vers", "iv": "AAAA", "data": "DDDD"}),
])


@pytest.fixture
def vault_id(admin):
    created = admin.post("/api/vaults", json={"name": "Team-Vault"}, headers=HEADERS)
    assert created.status_code == 201, created.text
    return created.json()["id"]


def share(admin, vault_id, subject, permission="readwrite", subject_type="user"):
    return admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={
        "entries": [{"subject_type": subject_type, "subject": subject, "permission": permission}]
    })


def write(client, vault_id, text, etag, token):
    return client.put(f"/api/vaults/{vault_id}/content", content=text,
                      headers={**HEADERS, "If-Match": f'"{etag}"', "X-Vault-Lock": token})


def lock(client, vault_id):
    return client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS)


# ------------------------------------------------------------------ managing


def test_a_new_vault_is_an_empty_shell(admin, vault_id):
    """The service cannot create a vault - it never sees the key."""
    listed = admin.get("/api/vaults").json()[0]
    assert listed["empty"] is True
    assert listed["etag"] is None
    # Even the creating administrator has no access without an entry.
    assert listed["permission"] is None
    assert listed["manage"] is True
    assert admin.get(f"/api/vaults/{vault_id}/content").status_code == 403


def test_an_administrator_needs_an_entry_like_everyone_else(admin, vault_id):
    share(admin, vault_id, "Admin")
    assert admin.get("/api/vaults").json()[0]["permission"] == "readwrite"
    assert admin.get(f"/api/vaults/{vault_id}/content").status_code == 204


def test_sharing_through_a_group(admin, vault_id, app):
    admin.post("/api/groups", json={"name": "team"}, headers=HEADERS)
    with user_client(app, "kollege@example.test") as client:
        group_id = admin.get("/api/groups").json()[0]["id"]
        admin.patch(f"/api/groups/{group_id}", headers=HEADERS, json={"members": ["Kollege"]})
        share(admin, vault_id, "team", "read", subject_type="group")
        listed = client.get("/api/vaults").json()
        assert len(listed) == 1
        assert listed[0]["permission"] == "read"


def test_the_wider_permission_wins(admin, vault_id, app):
    admin.post("/api/groups", json={"name": "team"}, headers=HEADERS)
    with user_client(app, "kollege@example.test") as client:
        group_id = admin.get("/api/groups").json()[0]["id"]
        admin.patch(f"/api/groups/{group_id}", headers=HEADERS, json={"members": ["Kollege"]})
        admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
            {"subject_type": "group", "subject": "team", "permission": "read"},
            {"subject_type": "user", "subject": "Kollege", "permission": "readwrite"},
        ]})
        assert client.get("/api/vaults").json()[0]["permission"] == "readwrite"


def test_a_vault_that_is_not_shared_stays_invisible(admin, vault_id, app):
    with user_client(app, "kollege@example.test") as client:
        assert client.get("/api/vaults").json() == []
        assert client.get(f"/api/vaults/{vault_id}/content").status_code == 403


def test_read_only_may_not_write(admin, vault_id, app):
    with user_client(app, "kollege@example.test") as client:
        share(admin, vault_id, "Kollege", "read")
        assert client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).status_code == 403


# ------------------------------------------------------------------- content


def test_the_write_roundtrip(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    result = write(admin, vault_id, VAULT_V2, "", token)
    assert result.status_code == 200, result.text
    etag = result.json()["etag"]
    read = admin.get(f"/api/vaults/{vault_id}/content")
    assert read.status_code == 200
    assert read.text == VAULT_V2
    assert read.headers["etag"].strip('"') == etag
    assert admin.get("/api/vaults").json()[0]["empty"] is False


def test_v3_with_version_blocks_is_accepted(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    assert write(admin, vault_id, VAULT_V3, "", token).status_code == 200


def test_nonsense_is_refused(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    for payload in ["", "keine json zeile", json.dumps({"type": "header", "format": "fremd"})]:
        assert write(admin, vault_id, payload, "", token).status_code == 400, payload
    assert admin.get(f"/api/vaults/{vault_id}/content").status_code == 204


def test_a_file_beyond_the_limit_is_refused(admin, vault_id):
    """413 before the body is read in full - not 400 after it sat in memory."""
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    assert admin.put("/api/settings", headers=HEADERS, json={"max_size_bytes": 1024}).status_code == 200
    padded = VAULT_V2 + "\n" + json.dumps({"type": "file", "id": "x", "iv": "A", "data": "B" * 2000})
    assert write(admin, vault_id, padded, "", token).status_code == 413
    assert admin.get(f"/api/vaults/{vault_id}/content").status_code == 204


def test_if_match_is_mandatory(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    result = admin.put(f"/api/vaults/{vault_id}/content", content=VAULT_V2,
                       headers={**HEADERS, "X-Vault-Lock": token})
    assert result.status_code == 428


def test_a_stale_etag_is_refused(admin, vault_id):
    """The layer that actually prevents a lost write."""
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    write(admin, vault_id, VAULT_V2, "", token)
    assert write(admin, vault_id, VAULT_V3, "", token).status_code == 412
    assert admin.get(f"/api/vaults/{vault_id}/content").text == VAULT_V2


def test_writing_without_a_lock_is_refused(admin, vault_id):
    share(admin, vault_id, "Admin")
    assert write(admin, vault_id, VAULT_V2, "", "kein-token").status_code == 409


# --------------------------------------------------------------------- locks


def test_a_second_person_does_not_get_the_lock(admin, vault_id, app):
    with user_client(app, "kollege@example.test") as client:
        admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
            {"subject_type": "user", "subject": "Admin", "permission": "readwrite"},
            {"subject_type": "user", "subject": "Kollege", "permission": "readwrite"},
        ]})
        lock(admin, vault_id)
        refused = client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS)
        assert refused.status_code == 409
        assert "Admin" in refused.json()["detail"]
        assert client.get(f"/api/vaults/{vault_id}/content").status_code == 204


def test_acquiring_twice_renews_instead_of_failing(admin, vault_id):
    share(admin, vault_id, "Admin")
    first = lock(admin, vault_id).json()
    second = lock(admin, vault_id).json()
    assert second["token"] == first["token"]
    assert second["expires_at"] >= first["expires_at"]


def test_an_expired_lock_counts_as_absent(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    db.init()
    with db.session_scope() as session:
        session.get(VaultLock, vault_id).expires_at = utcnow() - dt.timedelta(seconds=1)
    assert admin.put(f"/api/vaults/{vault_id}/lock",
                     headers={**HEADERS, "X-Vault-Lock": token}).status_code == 409
    assert lock(admin, vault_id).status_code == 200


def test_the_heartbeat_extends_the_lock(admin, vault_id):
    share(admin, vault_id, "Admin")
    acquired = lock(admin, vault_id).json()
    renewed = admin.put(f"/api/vaults/{vault_id}/lock",
                        headers={**HEADERS, "X-Vault-Lock": acquired["token"]})
    assert renewed.status_code == 200
    assert renewed.json()["expires_at"] >= acquired["expires_at"]


def test_releasing_needs_the_token(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    assert admin.request("DELETE", f"/api/vaults/{vault_id}/lock",
                         headers={**HEADERS, "X-Vault-Lock": "falsch"}).json()["released"] is False
    assert admin.request("DELETE", f"/api/vaults/{vault_id}/lock",
                         headers={**HEADERS, "X-Vault-Lock": token}).json()["released"] is True


def test_an_administrator_can_break_a_lock(admin, vault_id, app):
    with user_client(app, "kollege@example.test") as client:
        admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
            {"subject_type": "user", "subject": "Kollege", "permission": "readwrite"}]})
        held = client.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
        assert admin.request("DELETE", f"/api/vaults/{vault_id}/lock?force=1",
                             headers=HEADERS).json()["released"] is True
        assert client.put(f"/api/vaults/{vault_id}/lock",
                          headers={**HEADERS, "X-Vault-Lock": held}).status_code == 409


def test_only_administrators_may_break_a_lock(admin, vault_id, app):
    share(admin, vault_id, "Admin")
    lock(admin, vault_id)
    with user_client(app, "kollege@example.test") as client:
        assert client.request("DELETE", f"/api/vaults/{vault_id}/lock?force=1",
                              headers=HEADERS).status_code == 403


# ------------------------------------------------------------------- storage


def test_deleting_a_vault_removes_the_file(admin, vault_id):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    write(admin, vault_id, VAULT_V2, "", token)
    assert storage.exists(vault_id)
    assert admin.delete(f"/api/vaults/{vault_id}", headers=HEADERS).status_code == 200
    assert not storage.exists(vault_id)
    assert admin.get("/api/vaults").json() == []


def test_an_interrupted_write_leaves_the_previous_file(admin, vault_id, monkeypatch):
    share(admin, vault_id, "Admin")
    token = lock(admin, vault_id).json()["token"]
    etag = write(admin, vault_id, VAULT_V2, "", token).json()["etag"]

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("os.replace", explode)
    with pytest.raises(OSError):
        storage.write(vault_id, VAULT_V3)
    assert storage.read(vault_id) == VAULT_V2
    assert storage.compute_etag(storage.read(vault_id)) == etag
    assert list(storage.vault_dir(vault_id).glob(".write-*")) == []
