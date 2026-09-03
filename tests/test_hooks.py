"""Backup scripts: run after every save, and unable to break one."""

from __future__ import annotations

import json
import stat
import sys

import pytest

from mmo_vault.server import environment, hooks

from .conftest import HEADERS

WINDOWS = sys.platform == "win32"

VAULT = "\n".join([
    json.dumps({"type": "header", "format": "mmo-vault-v3", "salt": "AAAA", "iterations": 600000}),
    json.dumps({"type": "text", "iv": "AAAA", "data": "BBBB"}),
])


def write_script(name: str, body: str, *, executable: bool = True):
    """A script that runs on this platform, under the given base name.

    The service starts whatever it finds; on Windows that has to be a .cmd,
    on everything else a shell script. The bodies differ, what they do does not.
    """
    directory = environment.backup_scripts_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + (".cmd" if WINDOWS else ".sh"))
    path.write_text(body, encoding="utf-8")
    if executable and not WINDOWS:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def recorder(target: str) -> str:
    """A script that writes the vault name and file into `target`."""
    if WINDOWS:
        return f'@echo off\r\n>>"{target}" echo %MMO_VAULT_NAME%^|%MMO_VAULT_GENERATION%^|%MMO_VAULT_ACTOR%\r\n'
    return ('#!/bin/sh\n'
            f'printf "%s|%s|%s\\n" "$MMO_VAULT_NAME" "$MMO_VAULT_GENERATION" "$MMO_VAULT_ACTOR" >> "{target}"\n')


def failures(caplog) -> list[str]:
    """What the operator would find in `docker compose logs`."""
    return [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]


def successes(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelname == "INFO"]


# ------------------------------------------------------------------ selection


def test_without_the_directory_nothing_happens(configured):
    """The feature is off until somebody puts a script there."""
    assert not environment.backup_scripts_dir().exists() or hooks.scripts() == []
    hooks.run_all("v1", "Team", 1, "Admin")  # must not raise


def test_scripts_run_in_name_order(configured):
    write_script("20-second", recorder("x"))
    write_script("10-first", recorder("x"))
    assert [p.stem for p in hooks.scripts()] == ["10-first", "20-second"]


def test_hidden_and_shared_files_are_skipped(configured):
    write_script(".editor-leftover", recorder("x"))
    write_script("_common", recorder("x"))
    write_script("10-real", recorder("x"))
    assert [p.stem for p in hooks.scripts()] == ["10-real"]


@pytest.mark.skipif(WINDOWS, reason="Windows has no executable bit")
def test_a_script_without_the_executable_bit_is_parked(configured):
    """chmod -x is the off switch - no need to move the file away."""
    write_script("10-off", recorder("x"), executable=False)
    assert hooks.scripts() == []


# ---------------------------------------------------------------- environment


def test_a_script_learns_what_changed(configured, tmp_path):
    out = tmp_path / "seen.txt"
    write_script("10-record", recorder(out.as_posix()))
    hooks.run_all("vault-id", "Team-Vault", 7, "Admin")
    assert out.read_text(encoding="utf-8").strip().split("|") == ["Team-Vault", "7", "Admin"]


def test_the_environment_is_the_service_s_own_only_in_part(configured, monkeypatch):
    """A script gets what it needs, not the service's surroundings - a stray
    secret in the process environment does not travel along."""
    monkeypatch.setenv("SOME_OTHER_SECRET", "do-not-pass-this-on")
    env = hooks.environment_for("v1", "Team", 3, "Admin")
    assert "SOME_OTHER_SECRET" not in env
    assert env["MMO_VAULT_ID"] == "v1"
    assert env["MMO_VAULT_NAME"] == "Team"
    assert env["MMO_VAULT_GENERATION"] == "3"
    assert env["MMO_VAULT_FILE"].endswith("current.ndjson")
    assert "v1" in env["MMO_VAULT_FILE"]


# -------------------------------------------------------------------- failure


def test_a_failing_script_is_logged_and_raises_nothing(configured, caplog):
    body = ('@echo off\r\necho kaputt 1>&2\r\nexit /b 3\r\n' if WINDOWS
            else '#!/bin/sh\necho kaputt >&2\nexit 3\n')
    write_script("10-broken", body)
    with caplog.at_level("INFO", logger="mmo_vault.server.hooks"):
        hooks.run_all("v1", "Team", 1, "Admin")   # must not raise
    assert len(failures(caplog)) == 1
    assert "exited 3" in failures(caplog)[0] and "kaputt" in failures(caplog)[0]


def test_one_broken_script_does_not_stop_the_next(configured, tmp_path, caplog):
    out = tmp_path / "seen.txt"
    write_script("10-broken", '@echo off\r\nexit /b 1\r\n' if WINDOWS else '#!/bin/sh\nexit 1\n')
    write_script("20-good", recorder(out.as_posix()))
    with caplog.at_level("INFO", logger="mmo_vault.server.hooks"):
        hooks.run_all("v1", "Team", 1, "Admin")
    assert out.exists(), "the second script has to run even after the first failed"
    assert len(failures(caplog)) == 1
    assert len(successes(caplog)) == 1


def test_a_hanging_script_is_cut_off(configured, monkeypatch, caplog):
    monkeypatch.setattr(hooks, "TIMEOUT_SECONDS", 1)
    body = ('@echo off\r\nping -n 20 127.0.0.1 >nul\r\n' if WINDOWS
            else '#!/bin/sh\nsleep 20\n')
    write_script("10-hangs", body)
    with caplog.at_level("INFO", logger="mmo_vault.server.hooks"):
        hooks.run_all("v1", "Team", 1, "Admin")
    assert "timed out" in failures(caplog)[0]


# ---------------------------------------------------------------- integration


@pytest.fixture
def vault(admin):
    vault_id = admin.post("/api/vaults", json={"name": "Team-Vault"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "Admin", "permission": "readwrite"}]})
    token = admin.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
    return vault_id, token


def test_saving_runs_the_scripts(admin, vault, tmp_path):
    vault_id, token = vault
    out = tmp_path / "seen.txt"
    write_script("10-record", recorder(out.as_posix()))
    result = admin.put(f"/api/vaults/{vault_id}/content", content=VAULT,
                       headers={**HEADERS, "If-Match": '""', "X-Vault-Lock": token})
    assert result.status_code == 200
    assert out.read_text(encoding="utf-8").strip().split("|") == ["Team-Vault", "1", "Admin"]


def test_restoring_runs_them_too(admin, vault, tmp_path):
    """A restore changes the file like any other write."""
    vault_id, token = vault
    admin.put(f"/api/vaults/{vault_id}/content", content=VAULT,
              headers={**HEADERS, "If-Match": '""', "X-Vault-Lock": token})
    out = tmp_path / "seen.txt"
    write_script("10-record", recorder(out.as_posix()))
    assert admin.post(f"/api/vaults/{vault_id}/history/1/restore",
                      headers={**HEADERS, "X-Vault-Lock": token}).status_code == 200
    assert out.read_text(encoding="utf-8").strip().split("|") == ["Team-Vault", "2", "Admin"]


def test_a_broken_script_does_not_break_the_save(admin, vault, caplog):
    """The vault is written before the scripts run. Whatever they do, the
    person saving has already been told it worked."""
    vault_id, token = vault
    write_script("10-broken", '@echo off\r\nexit /b 1\r\n' if WINDOWS else '#!/bin/sh\nexit 1\n')
    with caplog.at_level("INFO", logger="mmo_vault.server.hooks"):
        result = admin.put(f"/api/vaults/{vault_id}/content", content=VAULT,
                           headers={**HEADERS, "If-Match": '""', "X-Vault-Lock": token})
    assert result.status_code == 200
    assert admin.get(f"/api/vaults/{vault_id}/content").text == VAULT
    assert len(failures(caplog)) == 1


def test_the_file_a_script_is_pointed_at_is_the_one_just_saved(admin, vault, tmp_path):
    vault_id, token = vault
    copy = tmp_path / "copy.ndjson"
    body = (f'@echo off\r\ncopy "%MMO_VAULT_FILE%" "{copy}" >nul\r\n' if WINDOWS
            else f'#!/bin/sh\ncp "$MMO_VAULT_FILE" "{copy.as_posix()}"\n')
    write_script("10-copy", body)
    admin.put(f"/api/vaults/{vault_id}/content", content=VAULT,
              headers={**HEADERS, "If-Match": '""', "X-Vault-Lock": token})
    assert copy.read_text(encoding="utf-8") == VAULT


def test_setup_creates_the_directory(configured):
    """Visible without reading the documentation first."""
    assert environment.backup_scripts_dir().is_dir()
