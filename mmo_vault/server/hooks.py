"""Backup hooks: whatever lies in <data dir>/backup_scripts runs after a save.

The service does not know how a site wants its backups done - to a second
disk, into a Nextcloud folder, onto a NAS - and it should not have to. It
offers a place to hang a script and one guarantee: after every successful
write the script runs, with the path of the file that just changed.

Three rules the implementation keeps to:

  it runs afterwards      as a background task, so a slow script never delays
                          the save or holds the lock
  it cannot break a save  a failing or hanging script is logged, never
                          raised - the vault is already written at that point
  it takes no input       the scripts are started directly, without a shell,
                          and everything they need arrives in the environment,
                          so no vault name can turn into a command
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from . import environment, storage

log = logging.getLogger(__name__)

# Long enough for copying a large vault plus an occ call, short enough that a
# hanging script does not tie up a worker for the rest of the day.
TIMEOUT_SECONDS = 120


def scripts() -> list[Path]:
    """The runnable scripts, in name order - 10-copy before 20-scan.

    Executable only. That is the on/off switch: chmod -x parks a script
    without moving it out of the way. Names starting with a dot or an
    underscore are skipped, so editor leftovers and shared includes stay out.
    """
    directory = environment.backup_scripts_dir()
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name.startswith((".", "_")):
            continue
        if not os.access(path, os.X_OK):
            log.warning("backup script %s is not executable - skipped", path.name)
            continue
        found.append(path)
    return found


def environment_for(vault_id: str, vault_name: str, generation: int, actor: str) -> dict[str, str]:
    """What a script gets. Deliberately not the whole process environment: a
    script should see what it needs, not the service's own surroundings."""
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "MMO_VAULT_ID": vault_id,
        "MMO_VAULT_NAME": vault_name,
        "MMO_VAULT_FILE": str(storage.current_path(vault_id)),
        "MMO_VAULT_DIR": str(environment.data_dir()),
        "MMO_VAULT_GENERATION": str(generation),
        "MMO_VAULT_ACTOR": actor,
    }


def run_all(vault_id: str, vault_name: str, generation: int, actor: str) -> None:
    """Runs every script and writes the outcome to the log.

    Called as a background task, after the response has gone out. Nothing here
    may raise: the vault is written at this point and the client has been told
    so - an exception could only be swallowed anyway.

    The outcome goes to the service log, not to the audit log: that one records
    what people did, and a backup script exiting non-zero is a matter for
    whoever reads `docker compose logs`. It also keeps this off the database
    entirely, which a background thread should not be touching mid-request.
    """
    found = scripts()
    if not found:
        return
    env = environment_for(vault_id, vault_name, generation, actor)
    for script in found:
        _run_one(script, env)


def _run_one(script: Path, env: dict[str, str]) -> bool:
    """True when the script ran and exited zero."""
    try:
        result = subprocess.run(
            [str(script)],
            env=env,
            cwd=str(script.parent),
            # No shell, no input, output collected rather than inherited: a
            # script that waits for a keypress must end at the timeout, not
            # hang forever.
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.error("backup script %s timed out after %ss", script.name, TIMEOUT_SECONDS)
        return False
    except OSError as err:
        # Missing interpreter, bad shebang, not executable after all.
        log.error("backup script %s could not be started: %s", script.name, err)
        return False

    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        message = tail[-1][:200] if tail else "no output"
        log.error("backup script %s exited %s: %s", script.name, result.returncode, message)
        return False

    log.info("backup script %s ok", script.name)
    return True
