"""Generations: every save is kept.

Nothing expires. That is the same decision the record versions in the vault
file follow, and for the same reason: a deadline that strikes in the background
deletes exactly when nobody is watching. Instead the size is shown, a mark is
named, and a person decides what goes.

Restoring writes a new generation rather than rewinding. The history therefore
stays gapless, and the restore itself can be undone.
"""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session as DbSession

from . import storage
from .models import Generation, User, Vault


def next_seq(db: DbSession, vault: Vault) -> int:
    """Takes the next number and moves the counter on.

    The counter lives on the vault instead of being derived from max(seq): a
    number taken from the existing rows would come back after a deletion, and
    two different states would end up looking like the same one.
    """
    seq = vault.next_generation or 1
    vault.next_generation = seq + 1
    return seq


def keep(
    db: DbSession, vault: Vault, text: str, author: User | None, note: str = ""
) -> Generation:
    seq = next_seq(db, vault)
    size = storage.write_generation(vault.id, seq, text)
    generation = Generation(
        vault_id=vault.id,
        seq=seq,
        author_id=author.id if author else None,
        size_bytes=size,
        sha256=storage.compute_etag(text),
        note=note[:255],
    )
    db.add(generation)
    return generation


def listing(db: DbSession, vault_id: str) -> list[Generation]:
    return list(
        db.query(Generation)
        .filter(Generation.vault_id == vault_id)
        .order_by(Generation.seq.desc())
    )


def total_bytes(db: DbSession, vault_id: str) -> int:
    total = (
        db.query(func.sum(Generation.size_bytes))
        .filter(Generation.vault_id == vault_id)
        .scalar()
    )
    return int(total or 0)


def to_json(db: DbSession, generation: Generation) -> dict:
    author = db.get(User, generation.author_id) if generation.author_id else None
    return {
        "seq": generation.seq,
        "created_at": generation.created_at.isoformat(),
        "author": author.name if author else None,
        "size_bytes": generation.size_bytes,
        "sha256": generation.sha256,
        "note": generation.note,
    }


def drop(db: DbSession, vault_id: str, seq: int) -> bool:
    generation = (
        db.query(Generation)
        .filter(Generation.vault_id == vault_id, Generation.seq == seq)
        .one_or_none()
    )
    if generation is None:
        return False
    db.delete(generation)
    storage.delete_generation(vault_id, seq)
    return True


def drop_many(db: DbSession, vault_id: str, before_seq: int | None = None) -> int:
    """Deletes the whole history, or everything below a sequence number.

    By sequence number rather than by date: the numbers are what the interface
    shows, and "everything before this one" is a question someone can answer
    while looking at the list.
    """
    query = db.query(Generation).filter(Generation.vault_id == vault_id)
    if before_seq is not None:
        query = query.filter(Generation.seq < before_seq)
    removed = 0
    for generation in list(query):
        storage.delete_generation(vault_id, generation.seq)
        db.delete(generation)
        removed += 1
    return removed
