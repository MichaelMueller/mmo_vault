"""A software authenticator for the tests.

Small enough to read in one go and real enough to be worth something: it
produces genuine ES256 signatures over genuine authenticator data, so the
verification in the service is exercised rather than mocked out.

Deliberately hand-written instead of pulling in soft-webauthn, which pins an
older `cryptography` and would drag the whole dependency set backwards.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url

# Authenticator data flags, in the order the specification lists them.
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_BACKUP_ELIGIBLE = 0x08
FLAG_BACKED_UP = 0x10
FLAG_ATTESTED_DATA = 0x40


class SoftAuthenticator:
    """One passkey on one imaginary device."""

    def __init__(self, *, backup_eligible: bool = True):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0
        self.backup_eligible = backup_eligible
        self.aaguid = b"\x00" * 16

    # ------------------------------------------------------------- internals

    def _flags(self, *, attested: bool) -> int:
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
        if self.backup_eligible:
            flags |= FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP
        if attested:
            flags |= FLAG_ATTESTED_DATA
        return flags

    def _cose_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,    # kty: EC2
                3: -7,   # alg: ES256
                -1: 1,   # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _authenticator_data(self, rp_id: str, *, attested: bool) -> bytes:
        data = hashlib.sha256(rp_id.encode()).digest()
        data += bytes([self._flags(attested=attested)])
        data += struct.pack(">I", self.sign_count)
        if attested:
            data += self.aaguid
            data += struct.pack(">H", len(self.credential_id))
            data += self.credential_id
            data += self._cose_key()
        return data

    @staticmethod
    def _client_data(kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()

    # ---------------------------------------------------------------- public

    def create(self, options: dict, origin: str) -> dict:
        """The answer to navigator.credentials.create()."""
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        auth_data = self._authenticator_data(options["rp"]["id"], attested=True)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
            },
        }

    def get(self, options: dict, origin: str) -> dict:
        """The answer to navigator.credentials.get()."""
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = self._authenticator_data(options["rpId"], attested=False)
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(b"1"),
            },
        }
