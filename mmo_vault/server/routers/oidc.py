"""Signing in through an external identity provider.

Two decisions shape this file:

  - The identity is the pair (issuer, subject), never the mail address. A
    provider that lets people choose their own address would otherwise be able
    to take over accounts.
  - An account is never created here. It is created by an administrator, and
    the identity is bound to it on the first sign-in. Whoever is not known is
    turned away - politely, and in the audit log.
"""

from __future__ import annotations

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DbSession

from .. import deps, sessions
from ..config import Config
from ..models import AuditLog, Group, Provider, User

router = APIRouter(prefix="/auth/oidc", tags=["auth"])


def _oauth_client(config: Config, provider: Provider):
    """One client per request rather than a registry.

    Providers can be added, changed and removed at runtime; a registry built
    once at start-up would quietly keep serving the old settings.
    """
    oauth = OAuth()
    oauth.register(
        name=provider.name,
        client_id=provider.client_id,
        client_secret=provider.client_secret,
        server_metadata_url=provider.issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": provider.scopes},
    )
    return oauth.create_client(provider.name)


def _allowed_provider_ids(user: User) -> set[int]:
    """Which providers this account may use: its own, plus those of its groups."""
    allowed = {user.provider_id} if user.provider_id else set()
    allowed |= {group.provider_id for group in user.groups if group.provider_id}
    return allowed


def _audit(db: DbSession, action: str, target: str, detail: str = "") -> None:
    db.add(AuditLog(action=action, target=target, detail=detail))


# Both endpoints are async: Authlib's Starlette integration returns coroutines,
# and a synchronous endpoint would hand FastAPI the coroutine object to
# serialise instead of a response. The database calls in here are few and short
# enough to live with on the event loop.
@router.get("/{name}")
async def begin(
    name: str,
    request: Request,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
):
    provider = db.query(Provider).filter(Provider.name == name, Provider.enabled.is_(True)).one_or_none()
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    client = _oauth_client(config, provider)
    # The redirect URI is built from the configured origin, not from the Host
    # header: a forged Host must not be able to steer the callback elsewhere.
    redirect_uri = f"{config.auth.origin.rstrip('/')}/auth/oidc/{provider.name}/callback"
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/{name}/callback")
async def callback(
    name: str,
    request: Request,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
):
    provider = db.query(Provider).filter(Provider.name == name, Provider.enabled.is_(True)).one_or_none()
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")

    client = _oauth_client(config, provider)
    try:
        token = await client.authorize_access_token(request)
    except OAuthError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err

    claims = token.get("userinfo") or {}
    subject = claims.get("sub")
    issuer = claims.get("iss") or provider.issuer
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token without a subject")

    user = _find_user(db, provider, issuer, subject, claims)
    if user is None:
        _audit(db, "oidc_login_denied", claims.get("email", "?"), f"provider={provider.name}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this account is not enabled for the service",
        )
    if provider.id not in _allowed_provider_ids(user):
        _audit(db, "oidc_login_denied", user.name, f"provider {provider.name} not allowed")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this provider is not allowed for this account",
        )

    deps.note_success(user)
    _audit(db, "oidc_login", user.name, f"provider={provider.name}")
    # The provider vouches for the second factor; the service does not ask for
    # another one.
    session = sessions.create(db, config, user, enrollment_only=False, request=request)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    sessions.attach_cookie(response, config, session)
    return response


def _find_user(
    db: DbSession, provider: Provider, issuer: str, subject: str, claims: dict
) -> User | None:
    """Finds the account behind an OIDC identity, and binds it once.

    Order matters: an already bound subject wins. Only when nothing is bound yet
    is the mail address consulted - and only if the provider vouches for it.
    """
    bound = (
        db.query(User)
        .filter(User.provider_id == provider.id, User.provider_subject == subject)
        .one_or_none()
    )
    if bound is not None:
        return bound if bound.is_active else None

    email = (claims.get("email") or "").strip().lower()
    if not email or not claims.get("email_verified"):
        # Without a verified address there is nothing that may be trusted for
        # the first binding.
        return None

    candidate = db.query(User).filter(User.email.ilike(email)).one_or_none()
    if candidate is None or not candidate.is_active:
        return None
    if provider.id not in _allowed_provider_ids(candidate):
        return None
    if candidate.provider_subject:
        # Already bound to a different subject at this provider - a second one
        # must not simply take over the account.
        return None

    candidate.provider_id = provider.id
    candidate.provider_subject = subject
    # The binding replaces the bootstrap: a password is no longer needed.
    candidate.must_enroll_passkey = False
    candidate.enroll_expires_at = None
    candidate.password_hash = None
    _audit(db, "oidc_bound", candidate.name, f"provider={provider.name} iss={issuer}")
    return candidate
