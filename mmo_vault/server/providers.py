"""What differs between identity providers, in one place.

Three things, and only these: how the issuer is derived, which claim carries a
trustworthy mail address, and which extra scope the group sync needs. Everything
else about a provider is the same OIDC dance through Authlib.
"""

from __future__ import annotations

from .config import Config
from .models import Provider

MICROSOFT = "microsoft"
GOOGLE = "google"
GENERIC = "generic"
KINDS = (MICROSOFT, GOOGLE, GENERIC)

# Tenant aliases that would let ANY Microsoft account in. Refused on purpose:
# without a concrete tenant there is no `tid` to check the address against, and
# Microsoft never sets email_verified.
MICROSOFT_OPEN_TENANTS = {"common", "organizations", "consumers"}

BASE_SCOPES = "openid email profile"
GROUP_SCOPES = {
    MICROSOFT: "GroupMember.Read.All",
    GOOGLE: "https://www.googleapis.com/auth/cloud-identity.groups.readonly",
}


class ProviderConfigError(ValueError):
    """The provider definition cannot work as given."""


def validate(kind: str, issuer: str, tenant: str | None) -> None:
    if kind not in KINDS:
        raise ProviderConfigError(f"unknown provider kind {kind!r}")
    if kind == MICROSOFT:
        if not tenant or tenant.strip().lower() in MICROSOFT_OPEN_TENANTS:
            raise ProviderConfigError(
                "a Microsoft provider needs a concrete tenant id or domain - "
                "'common' would admit any Microsoft account"
            )
    if kind == GENERIC and not issuer:
        raise ProviderConfigError("a generic provider needs an issuer URL")


def issuer_for(kind: str, tenant: str | None, issuer: str) -> str:
    if kind == MICROSOFT:
        return f"https://login.microsoftonline.com/{tenant.strip()}/v2.0"
    if kind == GOOGLE:
        return "https://accounts.google.com"
    return issuer.rstrip("/")


def scopes_for(kind: str, sync_groups: bool) -> str:
    extra = GROUP_SCOPES.get(kind) if sync_groups else None
    return f"{BASE_SCOPES} {extra}" if extra else BASE_SCOPES


def redirect_uri(config: Config, provider: Provider) -> str:
    # Built from the configured origin, never from the Host header: a forged
    # Host must not be able to steer the callback elsewhere.
    return f"{config.origin.rstrip('/')}/auth/oidc/{provider.name}/callback"


def verified_email(provider: Provider, claims: dict) -> str | None:
    """The address this provider vouches for - or None.

    Google and generic providers say so with email_verified. Microsoft never
    sets that claim; there the tenant is the guarantee: an account that carries
    OUR tenant id in `tid` has an address our tenant administers. Anything else
    is not an address we may trust for the allowlist.
    """
    if provider.kind == MICROSOFT:
        if (claims.get("tid") or "") != (provider.tenant or ""):
            return None
        address = claims.get("email") or claims.get("preferred_username") or ""
    else:
        if not claims.get("email_verified"):
            return None
        address = claims.get("email") or ""
    address = address.strip().lower()
    return address if "@" in address else None


def display_name(claims: dict, fallback: str) -> str:
    for key in ("name", "preferred_username", "email"):
        value = (claims.get(key) or "").strip()
        if value:
            return value[:128]
    return fallback
