"""Signing in through an identity provider - the only way in.

Three questions, answered in this order and by different parties:

  who is this?          the provider, through a verified claim
  may they come in?     the allowlist, per provider and address
  what may they do?     the admin flag (from the allowlist, every time) and the
                        groups and shares inside the service

An account is created by the first successful sign-in of an allowlisted address
and bound to (provider, subject) from then on. Nothing here is ever created by
hand, and nothing is ever admitted that the allowlist does not name.
"""

from __future__ import annotations

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DbSession

from .. import deps, providers, sessions
from ..config import Config
from ..models import Allowlist, AuditLog, Provider, User, utcnow

router = APIRouter(prefix="/auth/oidc", tags=["auth"])


def _oauth_client(provider: Provider):
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


def _audit(db: DbSession, action: str, target: str, detail: str = "", actor: User | None = None) -> None:
    db.add(AuditLog(actor_id=actor.id if actor else None, action=action, target=target, detail=detail))


def _provider_or_404(db: DbSession, name: str) -> Provider:
    provider = (
        db.query(Provider).filter(Provider.name == name, Provider.enabled.is_(True)).one_or_none()
    )
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    return provider


# Both endpoints are async: Authlib's Starlette integration returns coroutines,
# and a synchronous endpoint would hand FastAPI the coroutine object to
# serialise instead of a response.
@router.get("/{name}")
async def begin(
    name: str,
    request: Request,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
):
    provider = _provider_or_404(db, name)
    client = _oauth_client(provider)
    return await client.authorize_redirect(request, providers.redirect_uri(config, provider))


@router.get("/{name}/callback")
async def callback(
    name: str,
    request: Request,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
):
    provider = _provider_or_404(db, name)
    client = _oauth_client(provider)
    try:
        token = await client.authorize_access_token(request)
    except OAuthError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err

    claims = token.get("userinfo") or {}
    user = admit(db, provider, claims)
    if user is None:
        # One message for every reason: not on the list, address unverified,
        # account disabled. Which one is none of the caller's business.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this account is not enabled for the service",
        )

    # The provider vouched for the sign-in; the service asks for nothing more.
    session = sessions.create(db, config, user, request=request)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    sessions.attach_cookie(response, config, session)
    return response


def admit(db: DbSession, provider: Provider, claims: dict) -> User | None:
    """Decides whether this sign-in results in an account - and which.

    Pure database logic, kept apart from the HTTP dance so it can be tested
    without a provider. Returns the account to sign in, or None.
    """
    subject = (claims.get("sub") or "").strip()
    if not subject:
        _audit(db, "login_denied", provider.name, "token without a subject")
        return None

    email = providers.verified_email(provider, claims)
    entry = None
    if email:
        entry = (
            db.query(Allowlist)
            .filter(Allowlist.provider_id == provider.id, Allowlist.email == email)
            .one_or_none()
        )

    user = (
        db.query(User)
        .filter(User.provider_id == provider.id, User.provider_subject == subject)
        .one_or_none()
    )

    if user is not None:
        if entry is None:
            # Bound once, but no longer on the list: the account stays (with its
            # history) and stops working until an administrator lists it again
            # or deletes it.
            user.is_active = False
            _audit(db, "login_denied", user.name, f"{provider.name}: address no longer allowlisted")
            return None
        # The list is the authority on the role - every time, not just once.
        user.is_admin = entry.is_admin
        user.is_active = True
        user.email = email
        user.name = providers.display_name(claims, user.name)
        user.last_login_at = utcnow()
        _audit(db, "login", user.name, provider.name, actor=user)
        return user

    if entry is None:
        _audit(db, "login_denied", email or "?", f"{provider.name}: not allowlisted")
        return None

    # First sign-in of an allowlisted address: the account comes into being now
    # and is bound to the subject for good.
    user = User(
        name=providers.display_name(claims, email),
        email=email,
        provider_id=provider.id,
        provider_subject=subject,
        is_admin=entry.is_admin,
        is_active=True,
        last_login_at=utcnow(),
    )
    db.add(user)
    db.flush()
    _audit(db, "account_created", user.name, f"{provider.name}: first sign-in of {email}", actor=user)
    return user
