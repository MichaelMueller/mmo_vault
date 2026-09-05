"""Administration: providers, allowlist, accounts, groups, settings."""

from __future__ import annotations

from mmo_vault.server import db
from mmo_vault.server.models import Session, User, VaultAccess

from .conftest import ADMIN_EMAIL, HEADERS, sign_in, user_client


# ------------------------------------------------------------------ providers


def test_the_primary_provider_is_listed_first_and_its_secret_never(admin):
    listed = admin.get("/api/providers").json()
    assert listed[0]["is_primary"] is True
    assert listed[0]["redirect_uri"] == "https://vault.example/auth/oidc/idp/callback"
    assert "client_secret" not in listed[0]


def test_adding_a_microsoft_provider_needs_a_concrete_tenant(admin):
    refused = admin.post("/api/providers", headers=HEADERS, json={
        "name": "m365", "kind": "microsoft", "tenant": "common",
        "client_id": "c", "client_secret": "s"})
    assert refused.status_code == 400
    created = admin.post("/api/providers", headers=HEADERS, json={
        "name": "m365", "kind": "microsoft", "tenant": "contoso.onmicrosoft.com",
        "client_id": "c", "client_secret": "s", "sync_groups": True})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["issuer"] == "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
    assert "GroupMember.Read.All" in body["scopes"]


def test_a_provider_with_people_behind_it_cannot_be_deleted(admin):
    primary = admin.get("/api/providers").json()[0]
    assert admin.delete(f"/api/providers/{primary['id']}", headers=HEADERS).status_code == 409
    # The primary cannot be disabled either - somebody has to be able to sign in.
    assert admin.patch(f"/api/providers/{primary['id']}", headers=HEADERS,
                       json={"enabled": False}).status_code == 409


def test_making_another_provider_primary(admin):
    created = admin.post("/api/providers", headers=HEADERS, json={
        "name": "google", "kind": "google", "client_id": "c", "client_secret": "s"}).json()
    assert admin.patch(f"/api/providers/{created['id']}", headers=HEADERS,
                       json={"is_primary": True}).status_code == 200
    flags = {p["name"]: p["is_primary"] for p in admin.get("/api/providers").json()}
    assert flags == {"google": True, "idp": False}


# ------------------------------------------------------------------ allowlist


def test_allowlisting_admits_and_removing_disables(admin, app):
    primary = admin.get("/api/providers").json()[0]
    created = admin.post("/api/allowlist", headers=HEADERS, json={
        "provider_id": primary["id"], "email": "Kollege@Example.Test", "note": "Team"})
    assert created.status_code == 201
    assert created.json()["email"] == "kollege@example.test"
    assert created.json()["account_id"] is None  # not signed in yet

    with user_client(app, "kollege@example.test") as kollege:
        assert kollege.get("/api/me").status_code == 200
        entry = [e for e in admin.get("/api/allowlist").json() if e["email"] == "kollege@example.test"][0]
        assert entry["account_id"] is not None

        # Removing from the list ends the session and disables the account now.
        assert admin.delete(f"/api/allowlist/{entry['id']}", headers=HEADERS).status_code == 200
        assert kollege.get("/api/me").status_code == 401

    db.init()
    with db.session_scope() as session:
        assert session.query(User).filter(User.email == "kollege@example.test").one().is_active is False


def test_the_last_administrator_on_the_list_is_protected(admin):
    entry = admin.get("/api/allowlist").json()[0]
    assert entry["email"] == ADMIN_EMAIL
    assert admin.delete(f"/api/allowlist/{entry['id']}", headers=HEADERS).status_code == 409
    assert admin.patch(f"/api/allowlist/{entry['id']}", headers=HEADERS,
                       json={"is_admin": False}).status_code == 409

    primary = admin.get("/api/providers").json()[0]
    admin.post("/api/allowlist", headers=HEADERS, json={
        "provider_id": primary["id"], "email": "zweiter@example.test", "is_admin": True})
    # With a second administrator listed, demoting the first is allowed.
    assert admin.patch(f"/api/allowlist/{entry['id']}", headers=HEADERS,
                       json={"is_admin": False}).status_code == 200


def test_demotion_ends_the_running_session(admin, app):
    primary = admin.get("/api/providers").json()[0]
    admin.post("/api/allowlist", headers=HEADERS, json={
        "provider_id": primary["id"], "email": "zweiter@example.test", "is_admin": True})
    with user_client(app, "zweiter@example.test") as second:
        assert second.get("/api/users").status_code == 200
        entry = [e for e in admin.get("/api/allowlist").json() if e["email"] == "zweiter@example.test"][0]
        admin.patch(f"/api/allowlist/{entry['id']}", headers=HEADERS, json={"is_admin": False})
        # Not "still admin until the cookie expires": the session is gone.
        assert second.get("/api/users").status_code == 401


def test_duplicate_and_malformed_addresses_are_refused(admin):
    primary = admin.get("/api/providers").json()[0]
    assert admin.post("/api/allowlist", headers=HEADERS, json={
        "provider_id": primary["id"], "email": ADMIN_EMAIL}).status_code == 409
    assert admin.post("/api/allowlist", headers=HEADERS, json={
        "provider_id": primary["id"], "email": "keine-adresse"}).status_code == 400


# ------------------------------------------------------------------- accounts


def test_accounts_are_not_created_by_hand(admin):
    assert admin.post("/api/users", headers=HEADERS, json={"name": "x"}).status_code == 405


def test_a_normal_account_may_not_administer(admin, app):
    with user_client(app, "kollege@example.test") as kollege:
        assert kollege.get("/api/me").status_code == 200
        assert kollege.get("/api/users").status_code == 403
        assert kollege.get("/api/allowlist").status_code == 403


def test_disabling_an_account_revokes_its_sessions(admin, app):
    with user_client(app, "kollege@example.test") as kollege:
        user_id = kollege.get("/api/me").status_code == 200 and [
            u for u in admin.get("/api/users").json() if u["email"] == "kollege@example.test"][0]["id"]
        admin.patch(f"/api/users/{user_id}", headers=HEADERS, json={"is_active": False})
        assert kollege.get("/api/me").status_code == 401
    db.init()
    with db.session_scope() as session:
        assert session.query(Session).filter(Session.user_id == user_id).count() == 0


def test_deleting_an_account_leaves_no_shares_behind(admin, app):
    """The review finding, carried over: a leftover vault_access row would
    grant a later account the permissions of the deleted one."""
    with user_client(app, "kollege@example.test"):
        pass
    user_id = [u for u in admin.get("/api/users").json() if u["email"] == "kollege@example.test"][0]["id"]
    vault_id = admin.post("/api/vaults", json={"name": "V"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "Kollege", "permission": "readwrite"}]})

    assert admin.delete(f"/api/users/{user_id}", headers=HEADERS).status_code == 200
    db.init()
    with db.session_scope() as session:
        assert session.query(VaultAccess).filter(VaultAccess.subject_id == user_id).count() == 0


# --------------------------------------------------------------------- groups


def test_local_groups_and_membership(admin, app):
    assert admin.post("/api/groups", headers=HEADERS, json={"name": "team"}).status_code == 201
    with user_client(app, "kollege@example.test"):
        pass
    group_id = admin.get("/api/groups").json()[0]["id"]
    updated = admin.patch(f"/api/groups/{group_id}", headers=HEADERS, json={"members": ["Kollege"]})
    assert updated.status_code == 200
    assert updated.json()["members"] == ["Kollege"]
    assert updated.json()["source"] == "local"
    # Unknown accounts are an error, not silently dropped.
    assert admin.patch(f"/api/groups/{group_id}", headers=HEADERS,
                       json={"members": ["niemand"]}).status_code == 400


def test_deleting_a_group_takes_its_shares(admin):
    admin.post("/api/groups", headers=HEADERS, json={"name": "team"})
    group_id = admin.get("/api/groups").json()[0]["id"]
    vault_id = admin.post("/api/vaults", json={"name": "V"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "group", "subject": "team", "permission": "readwrite"}]})
    assert admin.delete(f"/api/groups/{group_id}", headers=HEADERS).status_code == 200
    db.init()
    with db.session_scope() as session:
        assert session.query(VaultAccess).filter(
            VaultAccess.subject_type == "group", VaultAccess.subject_id == group_id).count() == 0


# ------------------------------------------------------------------- settings


def test_settings_round_trip_and_take_effect_without_restart(admin):
    before = admin.get("/api/settings").json()
    assert before["session_hours"] == 12
    assert "secret_key" not in before

    assert admin.put("/api/settings", headers=HEADERS,
                     json={"session_hours": 4, "lock_ttl_seconds": 120}).status_code == 200
    after = admin.get("/api/settings").json()
    assert after["session_hours"] == 4
    assert after["lock_ttl_seconds"] == 120
    # Untouched values keep their defaults.
    assert after["session_idle_minutes"] == 30


def test_the_origin_has_to_be_https(admin):
    assert admin.put("/api/settings", headers=HEADERS,
                     json={"origin": "http://vault.example"}).status_code == 400
    assert admin.put("/api/settings", headers=HEADERS,
                     json={"origin": "https://neu.example/"}).status_code == 200
    assert admin.get("/api/providers").json()[0]["redirect_uri"].startswith("https://neu.example/")


# ---------------------------------------------------------------------- pages


def test_pages(admin, anonymous):
    assert admin.get("/admin").status_code == 200
    assert "window.mmoVaultServer" in admin.get("/").text
    assert anonymous.get("/", follow_redirects=False).headers["location"] == "/login"
    assert anonymous.get("/admin").status_code == 401
    page = anonymous.get("/login").text
    assert "/auth/oidc/idp" in page
    assert "password" not in page.lower()


# ------------------------------------------------------------------- design


def test_the_pages_bring_their_own_stylesheet_and_fonts(anonymous):
    """Served, not inlined - that is what lets the policy below stay strict."""
    for path in ("/static/vault.css", "/static/api.js", "/static/admin.js",
                 "/static/fonts/inter-latin-400.woff2"):
        assert anonymous.get(path).status_code == 200, path


def test_no_inline_style_or_script_on_the_service_pages(admin, anonymous):
    """The policy forbids both, so an inline attribute would silently do
    nothing - the kind of bug that only shows up as a crooked layout."""
    for page in (anonymous.get("/login"), admin.get("/admin")):
        policy = page.headers.get("content-security-policy", "")
        assert "frame-ancestors 'none'" in policy
        assert 'style="' not in page.text
        assert "<script>" not in page.text
        meta = page.text.split('http-equiv="Content-Security-Policy" content="')[1].split('"')[0]
        assert "style-src 'self'" in meta and "script-src 'self'" in meta
        assert "unsafe-inline" not in meta


def test_the_administration_asks_with_dialogs_not_with_prompt(admin):
    """A share used to be typed as `mueller, #team!` into a one-line system
    box. Unguessable, and on a phone uncorrectable."""
    page = admin.get("/admin").text
    script = admin.get("/static/admin.js").text
    assert "<dialog" in page
    # The word survives in a comment explaining why it is gone; the call does not.
    assert "prompt('" not in script and 'prompt("' not in script
    # Deletions stay a plain yes/no question; that one works everywhere.
    assert "confirm(" in script
