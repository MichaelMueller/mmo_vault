"""Command line of the server variant: setup, start, export-vault.

Two things come from the environment - where the data directory is and where
the database is. Everything `setup` asks for goes into the database.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from . import config as settings
from . import db, environment, migrations, providers
from .models import Allowlist, Provider


# --------------------------------------------------------------------- input


def _ask(prompt: str, default: str | None = None, *, non_interactive: bool = False,
         secret: bool = False) -> str:
    if non_interactive:
        if default is None:
            raise SystemExit(f"missing value for '{prompt}' in non-interactive mode")
        return default
    suffix = f" [{default}]" if default is not None else ""
    answer = (getpass.getpass if secret else input)(f"{prompt}{suffix}: ").strip()
    return answer or (default or "")


def _ask_yes_no(prompt: str, default: bool, *, non_interactive: bool = False) -> bool:
    if non_interactive:
        return default
    hint = "J/n" if default else "j/N"
    answer = input(f"{prompt} [{hint}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"j", "ja", "y", "yes"}


# --------------------------------------------------------------------- setup


def cmd_setup(args: argparse.Namespace) -> int:
    non_interactive = args.non_interactive
    data_dir = environment.data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    environment.vaults_dir().mkdir(exist_ok=True)
    # Created empty, so the place to hang a backup script is visible without
    # having to read the documentation first.
    environment.backup_scripts_dir().mkdir(exist_ok=True)

    print("MMO Vault - setting up the server variant\n")
    print(f"Data directory: {data_dir}")
    print(f"Database:       {environment.database_url()}\n")

    # Through Alembic, not create_all: the version table has to be stamped, or
    # the next real migration trips over tables that already exist.
    db.init()
    migrations.upgrade_to_head(environment.database_url())

    with db.session_scope() as session:
        existing_primary = session.query(Provider).filter(Provider.is_primary.is_(True)).one_or_none()
        if existing_primary is not None and not args.force:
            print(f"There is already a primary provider ('{existing_primary.name}').")
            print("Use --force to replace its credentials and add administrators. Nothing is deleted.")
            return 1

        config = settings.ensure_secret_key(session, settings.load(session))

        # 1. Origin -------------------------------------------------------
        print("The public address of the service. The providers' redirect URIs are\n"
              "built from it, so it has to be right before the first sign-in.")
        origin = _ask("Origin (with scheme)", args.origin or config.origin or None,
                      non_interactive=non_interactive).rstrip("/")
        if not origin.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise SystemExit("the origin must be https:// (plain http only for localhost)")
        config.origin = origin

        # 2. Primary provider ---------------------------------------------
        print("\nThe primary identity provider. Further ones can be added in the\n"
              "administration later.")
        kind = _ask("Kind (microsoft / google / generic)",
                    args.kind or (existing_primary.kind if existing_primary else "microsoft"),
                    non_interactive=non_interactive).strip().lower()
        name = _ask("Name (short, lower case)",
                    args.provider_name or (existing_primary.name if existing_primary else kind),
                    non_interactive=non_interactive).strip().lower()
        tenant = None
        issuer = ""
        if kind == providers.MICROSOFT:
            print("The tenant id or the tenant domain (e.g. contoso.onmicrosoft.com).\n"
                  "'common' is refused: it would admit any Microsoft account.")
            tenant = _ask("Tenant", args.tenant or (existing_primary.tenant if existing_primary else None),
                          non_interactive=non_interactive)
        elif kind == providers.GENERIC:
            issuer = _ask("Issuer URL", args.issuer or (existing_primary.issuer if existing_primary else None),
                          non_interactive=non_interactive)
        client_id = _ask("Client ID", args.client_id or (existing_primary.client_id if existing_primary else None),
                         non_interactive=non_interactive)
        client_secret = _ask("Client secret", args.client_secret, non_interactive=non_interactive, secret=True)
        sync_groups = _ask_yes_no("Mirror this provider's groups on sign-in?",
                                  args.sync_groups, non_interactive=non_interactive)
        try:
            providers.validate(kind, issuer, tenant)
        except providers.ProviderConfigError as err:
            raise SystemExit(str(err))

        provider = existing_primary or session.query(Provider).filter(Provider.name == name).one_or_none()
        if provider is None:
            provider = Provider(name=name)
            session.add(provider)
        provider.kind = kind
        provider.tenant = tenant.strip() if tenant else None
        provider.issuer = providers.issuer_for(kind, tenant, issuer)
        provider.client_id = client_id
        provider.client_secret = client_secret
        provider.scopes = providers.scopes_for(kind, sync_groups)
        provider.sync_groups = sync_groups
        provider.enabled = True
        session.query(Provider).filter(Provider.name != name).update({Provider.is_primary: False})
        provider.is_primary = True
        session.flush()

        # 3. Administrators -----------------------------------------------
        print("\nThe first administrators: mail addresses at this provider, comma separated.\n"
              "They may sign in right away; everyone else has to be allowlisted by them.")
        raw = _ask("Administrators", args.admins, non_interactive=non_interactive)
        emails = sorted({e.strip().lower() for e in raw.split(",") if "@" in e})
        if not emails:
            raise SystemExit("at least one administrator address is required")
        for email in emails:
            entry = session.query(Allowlist).filter(
                Allowlist.provider_id == provider.id, Allowlist.email == email
            ).one_or_none()
            if entry is None:
                session.add(Allowlist(provider_id=provider.id, email=email, is_admin=True,
                                      note="initial administrator"))
            else:
                entry.is_admin = True

        settings.save(session, config)

    print(f"\nProvider '{name}' ({kind}) is primary.")
    print(f"Redirect URI to register at the provider:\n  {origin}/auth/oidc/{name}/callback")
    print(f"Administrators: {', '.join(emails)}")
    print("\nNext:")
    print("  python mmo_vault.py start")
    print(f"  then sign in at {origin} - the administration lives at {origin}/admin")
    return 0


# --------------------------------------------------------------------- start


def cmd_start(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import readiness_problems

    engine = db.init()
    if migrations.pending_migrations(engine):
        print("The database schema is out of date.\n"
              "Run `python mmo_vault.py setup --force` or `alembic upgrade head`.", file=sys.stderr)
        return 1
    with db.session_scope() as session:
        problems = readiness_problems(session)
        config = settings.load(session)
    if problems:
        print("The service is not set up yet - missing: " + ", ".join(problems) + ".\n"
              "Run `python mmo_vault.py setup` first.", file=sys.stderr)
        return 1

    host = args.host or config.server.host
    port = args.port or config.server.port
    print(f"MMO Vault on http://{host}:{port}  (origin {config.origin})")
    uvicorn.run(
        "mmo_vault.server.app:create_app",
        factory=True,
        host=host,
        port=port,
        workers=None if args.reload else config.server.workers,
        reload=args.reload,
        proxy_headers=config.server.proxy_headers,
        forwarded_allow_ips=(config.server.forwarded_allow_ips if config.server.proxy_headers else None),
    )
    return 0


# -------------------------------------------------------------- export-vault


def cmd_export_vault(args: argparse.Namespace) -> int:
    """The way out when the provider is not there.

    Whoever has the shell gets the encrypted file and opens it locally with the
    master password. The service itself cannot read it - and neither can this
    command; it prints ciphertext.
    """
    from . import storage
    from .models import Vault

    db.init()
    with db.session_scope() as session:
        vault = session.get(Vault, args.vault_id)
        if vault is None:
            match = session.query(Vault).filter(Vault.name == args.vault_id).all()
            if len(match) == 1:
                vault = match[0]
        if vault is None:
            print(f"No vault with id or unique name '{args.vault_id}'.", file=sys.stderr)
            return 1
        text = (storage.read_generation(vault.id, args.generation) if args.generation
                else storage.read(vault.id))
    if text is None:
        print("Nothing stored for that vault/generation.", file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


# ----------------------------------------------------------------- arguments


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mmo_vault.py",
        description="MMO Vault - server variant. Configuration: MMO_VAULT_DIR, MMO_VAULT_DATABASE_URL.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="first-time setup: origin, primary provider, administrators")
    setup.add_argument("--force", action="store_true", help="replace the primary provider's credentials")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--origin")
    setup.add_argument("--kind", choices=list(providers.KINDS))
    setup.add_argument("--provider-name")
    setup.add_argument("--tenant")
    setup.add_argument("--issuer")
    setup.add_argument("--client-id")
    setup.add_argument("--client-secret")
    setup.add_argument("--sync-groups", action="store_true")
    setup.add_argument("--admins", help="comma separated mail addresses")
    setup.set_defaults(func=cmd_setup)

    start = sub.add_parser("start", help="run the service")
    start.add_argument("--host")
    start.add_argument("--port", type=int)
    start.add_argument("--reload", action="store_true", help="for development")
    start.set_defaults(func=cmd_start)

    export = sub.add_parser("export-vault", help="print a vault's ciphertext to stdout")
    export.add_argument("vault_id", help="vault id, or its name if unique")
    export.add_argument("--generation", type=int, help="a kept generation instead of the current file")
    export.set_defaults(func=cmd_export_vault)

    return parser


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, str(environment.PROJECT_ROOT))
    args = build_parser().parse_args(argv)
    return args.func(args)
