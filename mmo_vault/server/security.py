"""Random identifiers.

This used to hold password and backup-code hashing. Both are gone: the service
keeps no local credentials any more, identity comes from the OIDC provider.
What remains is the one primitive everything else needs - an identifier that
cannot be guessed.
"""

from __future__ import annotations

import secrets


def new_session_id() -> str:
    """256 bits from the OS. Used for sessions, lock tokens and OAuth state."""
    return secrets.token_urlsafe(32)
