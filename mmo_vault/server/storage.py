"""Reading and writing vault files on disk.

The service never looks inside. It checks that what arrives is structurally a
vault file and how big it is - nothing else. The content is ciphertext, and the
key never comes near this machine.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from .config import VAR_DIR

VAULTS_DIR = VAR_DIR / "vaults"
CURRENT_NAME = "current.ndjson"
HISTORY_NAME = "history"

# The formats the application writes. A file that claims something else is
# rejected rather than stored and handed back later as garbage.
KNOWN_FORMATS = {"mmo-vault-v1", "mmo-vault-v2", "mmo-vault-v3"}


class InvalidVault(ValueError):
    """The payload is not a vault file."""


def vault_dir(vault_id: str) -> Path:
    return VAULTS_DIR / vault_id


def current_path(vault_id: str) -> Path:
    return vault_dir(vault_id) / CURRENT_NAME


def exists(vault_id: str) -> bool:
    return current_path(vault_id).is_file()


def compute_etag(text: str) -> str:
    """An ETag that follows from the content.

    Deliberately not a counter: two writes with identical content produce the
    same tag, and a restored generation is recognisable as what it is.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate(text: str, max_bytes: int) -> None:
    """Structural check only - never a look at the content.

    Without this, a mistyped upload would be stored happily and only fall over
    in the browser of whoever opens the vault next.
    """
    size = len(text.encode("utf-8"))
    if size == 0:
        raise InvalidVault("empty file")
    if size > max_bytes:
        raise InvalidVault(f"file is larger than the limit of {max_bytes} bytes")

    lines = [line for line in text.strip().split("\n") if line.strip()]
    try:
        first = json.loads(lines[0])
    except json.JSONDecodeError as err:
        raise InvalidVault("first line is not JSON") from err

    if first.get("type") == "header":
        if first.get("format") not in KNOWN_FORMATS:
            raise InvalidVault(f"unknown format {first.get('format')!r}")
        for number, line in enumerate(lines[1:], start=2):
            try:
                json.loads(line)
            except json.JSONDecodeError as err:
                raise InvalidVault(f"line {number} is not JSON") from err
        return

    # Legacy v1: one single object with everything in it.
    if all(key in first for key in ("salt", "iterations", "iv", "data")):
        return
    raise InvalidVault("neither a block header nor a v1 file")


def read(vault_id: str) -> str | None:
    path = current_path(vault_id)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def write(vault_id: str, text: str) -> tuple[str, int]:
    """Writes atomically and returns (etag, size).

    Temporary file plus os.replace: a crash halfway through leaves the previous
    file untouched instead of a truncated one. The same reasoning as the
    rollback in the browser, one layer further down.
    """
    directory = vault_dir(vault_id)
    directory.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")

    handle, temp_name = tempfile.mkstemp(dir=directory, prefix=".write-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(data)
            file.flush()
            # Without this the rename can land before the data does, and a power
            # loss leaves an entry pointing at nothing.
            os.fsync(file.fileno())
        os.replace(temp_name, current_path(vault_id))
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise

    return compute_etag(text), len(data)


# ------------------------------------------------------------------ history


def history_dir(vault_id: str) -> Path:
    return vault_dir(vault_id) / HISTORY_NAME


def generation_path(vault_id: str, seq: int) -> Path:
    # The sequence number is padded so a directory listing sorts the way the
    # generations happened.
    return history_dir(vault_id) / f"{seq:06d}.ndjson"


def write_generation(vault_id: str, seq: int, text: str) -> int:
    """Keeps a copy beside the current file.

    Written with the same care as the current file: a generation that only
    exists half way would be worse than none at all, because it looks like a
    valid one to restore from.
    """
    directory = history_dir(vault_id)
    directory.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")

    handle, temp_name = tempfile.mkstemp(dir=directory, prefix=".write-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, generation_path(vault_id, seq))
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
    return len(data)


def read_generation(vault_id: str, seq: int) -> str | None:
    path = generation_path(vault_id, seq)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def delete_generation(vault_id: str, seq: int) -> None:
    generation_path(vault_id, seq).unlink(missing_ok=True)


def delete(vault_id: str) -> None:
    """Removes the vault including everything kept beside it."""
    directory = vault_dir(vault_id)
    if not directory.exists():
        return
    for path in sorted(directory.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        else:
            path.rmdir()
    directory.rmdir()
