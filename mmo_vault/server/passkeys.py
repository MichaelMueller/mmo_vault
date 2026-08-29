"""WebAuthn: registering and using passkeys.

Everything the library needs is derived from the configuration - above all the
RP ID and the origin, which are asked for during setup rather than taken from
the Host header. A request header must never decide what a credential is bound
to; that would let an attacker with a fake Host register credentials that are
valid elsewhere.
"""

from __future__ import annotations

import datetime as dt
import json

import webauthn
from webauthn.helpers import base64url_to_bytes, options_to_json
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from sqlalchemy.orm import Session as DbSession

from .config import Config
from .models import Credential, User, WebAuthnChallenge, utcnow
from .security import new_session_id

# A challenge is answered within seconds. Anything older is not a slow user but
# a replay attempt or a forgotten browser tab.
CHALLENGE_TTL = dt.timedelta(minutes=5)


class PasskeyError(Exception):
    """Registration or authentication was rejected."""


# ------------------------------------------------------------------ challenges


def _store_challenge(
    db: DbSession, challenge: bytes, purpose: str, user_id: int | None
) -> str:
    # Housekeeping on the way in: the options endpoints are reachable without a
    # session, so anyone can create rows here. Purging on every store bounds
    # the table to five minutes of request rate instead of letting it grow for
    # the lifetime of the database.
    purge_expired_challenges(db)
    record = WebAuthnChallenge(
        id=new_session_id(),
        challenge=challenge,
        purpose=purpose,
        user_id=user_id,
        expires_at=utcnow() + CHALLENGE_TTL,
    )
    db.add(record)
    return record.id


def _take_challenge(db: DbSession, challenge_id: str, purpose: str) -> WebAuthnChallenge:
    """Fetches a challenge and consumes it - one attempt per challenge."""
    record = db.get(WebAuthnChallenge, challenge_id or "")
    if record is None or record.purpose != purpose:
        raise PasskeyError("unknown challenge")
    db.delete(record)
    if record.expires_at <= utcnow():
        raise PasskeyError("challenge expired")
    return record


def purge_expired_challenges(db: DbSession) -> int:
    count = (
        db.query(WebAuthnChallenge)
        .filter(WebAuthnChallenge.expires_at <= utcnow())
        .delete()
    )
    return int(count or 0)


# ---------------------------------------------------------------- registration


def registration_options(db: DbSession, config: Config, user: User) -> tuple[str, dict]:
    """Returns (challenge_id, options) for navigator.credentials.create()."""
    options = webauthn.generate_registration_options(
        rp_id=config.auth.rp_id,
        rp_name=config.auth.rp_name,
        # The user handle must not be the name: it ends up on the authenticator
        # and would leak a rename into every device.
        user_id=str(user.id).encode(),
        user_name=user.name,
        user_display_name=user.name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            # Discoverable, so signing in works without typing a name, and with
            # user verification so possession alone is not enough.
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        # Keeps a device from registering itself twice for the same account.
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=credential.credential_id)
            for credential in user.credentials
        ],
    )
    challenge_id = _store_challenge(db, options.challenge, "register", user.id)
    return challenge_id, json.loads(options_to_json(options))


def verify_registration(
    db: DbSession, config: Config, user: User, challenge_id: str, credential: dict, label: str
) -> Credential:
    record = _take_challenge(db, challenge_id, "register")
    if record.user_id != user.id:
        raise PasskeyError("challenge belongs to a different account")
    try:
        verified = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=record.challenge,
            expected_rp_id=config.auth.rp_id,
            expected_origin=config.auth.origin,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as err:
        raise PasskeyError(str(err)) from err

    stored = Credential(
        user_id=user.id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        label=(label or "").strip()[:64],
        # Whether this credential is synced. Used to tell a user whose only
        # passkey would not survive losing the device.
        backup_eligible=bool(verified.credential_backed_up),
    )
    db.add(stored)
    return stored


# -------------------------------------------------------------- authentication


def authentication_options(
    db: DbSession, config: Config, user: User | None
) -> tuple[str, dict]:
    """Challenge for navigator.credentials.get().

    Without a user the credentials stay open: the passkey is discoverable, the
    browser picks it, and the service does not have to disclose whether an
    account exists.
    """
    options = webauthn.generate_authentication_options(
        rp_id=config.auth.rp_id,
        user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=(
            [
                PublicKeyCredentialDescriptor(id=credential.credential_id)
                for credential in user.credentials
            ]
            if user is not None
            else None
        ),
    )
    challenge_id = _store_challenge(
        db, options.challenge, "authenticate", user.id if user else None
    )
    return challenge_id, json.loads(options_to_json(options))


def verify_authentication(
    db: DbSession, config: Config, challenge_id: str, credential: dict
) -> Credential:
    record = _take_challenge(db, challenge_id, "authenticate")

    raw_id = credential.get("rawId") or credential.get("id")
    if not raw_id:
        raise PasskeyError("response without a credential id")
    try:
        credential_id = base64url_to_bytes(raw_id)
    except Exception as err:  # noqa: BLE001 - malformed input, not a bug
        raise PasskeyError("malformed credential id") from err

    stored = (
        db.query(Credential).filter(Credential.credential_id == credential_id).one_or_none()
    )
    if stored is None:
        raise PasskeyError("unknown passkey")
    if record.user_id is not None and record.user_id != stored.user_id:
        raise PasskeyError("passkey belongs to a different account")

    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=record.challenge,
            expected_rp_id=config.auth.rp_id,
            expected_origin=config.auth.origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as err:
        raise PasskeyError(str(err)) from err

    # A counter that fails to move forward can mean a cloned authenticator.
    # Many modern ones stay at zero, which is allowed; the library checks the
    # case that actually matters.
    stored.sign_count = verified.new_sign_count
    stored.last_used_at = utcnow()
    stored.backup_eligible = bool(verified.credential_backed_up)
    return stored
