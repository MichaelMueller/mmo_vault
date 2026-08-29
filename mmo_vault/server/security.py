"""Passwords, recovery codes and session identifiers.

Passkeys themselves arrive in phase 2; what lives here is everything the
bootstrap needs: a password hash that is only ever a temporary way in, and the
one-time codes that are the way back when a device is lost.
"""

from __future__ import annotations

import datetime as dt
import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .models import utcnow

# Defaults of argon2-cffi, which follow the OWASP recommendation for Argon2id.
_hasher = PasswordHasher()

MIN_PASSWORD_LENGTH = 12
BACKUP_CODE_COUNT = 8
# Crockford-ish: no I, O, 0, 1 - these codes get read aloud and typed off paper.
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(hashed: str | None, password: str) -> bool:
    """False instead of an exception: a caller must not have to distinguish
    between a wrong password and a missing hash."""
    if not hashed:
        return False
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


def password_problem(password: str) -> str | None:
    """Returns a reason why this password is unacceptable, or None.

    Deliberately a floor and not a scoring system: this password exists for
    minutes, until a passkey is registered.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"at least {MIN_PASSWORD_LENGTH} characters"
    if password.strip() != password:
        return "no leading or trailing spaces"
    if len(set(password)) < 5:
        return "too few different characters"
    return None


def generate_password(length: int = 20) -> str:
    """For `enroll`, where the machine picks the one-time password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_backup_code(code: str) -> str:
    return _hasher.hash(normalise_backup_code(code))


def normalise_backup_code(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


def verify_backup_code(hashed: str, code: str) -> bool:
    try:
        return _hasher.verify(hashed, normalise_backup_code(code))
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def enrollment_deadline(hours: int) -> dt.datetime:
    """Naive UTC, following the convention in models.utcnow()."""
    return utcnow() + dt.timedelta(hours=hours)
