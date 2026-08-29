"""Command line of the server variant: setup, start, enroll.

`setup` is deliberately interactive with sensible defaults, and every question
also exists as a flag so an unattended run in a container works too.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import sys
from pathlib import Path

from . import db, migrations, security
from .config import PROJECT_ROOT, VAR_DIR, Config, ConfigMissing, new_secret_key
from .models import User


# --------------------------------------------------------------------- input


def _ask(prompt: str, default: str | None = None, *, non_interactive: bool = False) -> str:
    if non_interactive:
        if default is None:
            raise SystemExit(f"missing value for '{prompt}' in non-interactive mode")
        return default
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or (default or "")


def _ask_yes_no(prompt: str, default: bool, *, non_interactive: bool = False) -> bool:
    if non_interactive:
        return default
    hint = "J/n" if default else "j/N"
    answer = input(f"{prompt} [{hint}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"j", "ja", "y", "yes"}


def _ask_password(non_interactive: bool = False, given: str | None = None) -> str:
    if given:
        problem = security.password_problem(given)
        if problem:
            raise SystemExit(f"password rejected: {problem}")
        return given
    if non_interactive:
        raise SystemExit("--admin-password is required in non-interactive mode")
    while True:
        first = getpass.getpass("Password for the administrator: ")
        problem = security.password_problem(first)
        if problem:
            print(f"  rejected: {problem}")
            continue
        second = getpass.getpass("Repeat password: ")
        if first != second:
            print("  the two entries differ")
            continue
        return first


# --------------------------------------------------------------------- setup


def cmd_setup(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if args.config else None
    target = config_path or (VAR_DIR / "config.toml")
    if target.exists() and not args.force:
        print(f"There is already a configuration at {target}.")
        print("Use --force to change settings. Existing accounts are kept.")
        return 1

    non_interactive = args.non_interactive
    print("MMO Vault - setting up the server variant\n")

    config = Config()
    if target.exists():
        config = Config.load(target)

    # 1. Database ------------------------------------------------------------
    config.database_url = _ask(
        "Database URL", args.database_url or config.database_url,
        non_interactive=non_interactive,
    )

    # 2. Public identity, needed for passkeys --------------------------------
    print(
        "\nPasskeys are bound to a domain name. A later change invalidates every\n"
        "registered passkey, so this is asked for rather than guessed."
    )
    config.auth.rp_id = _ask(
        "Domain name (RP ID)", args.rp_id or config.auth.rp_id,
        non_interactive=non_interactive,
    )
    default_origin = args.origin or (
        config.auth.origin if config.auth.rp_id == "localhost" else f"https://{config.auth.rp_id}"
    )
    config.auth.origin = _ask("Origin (with scheme)", default_origin, non_interactive=non_interactive)

    # 3. Uvicorn -------------------------------------------------------------
    config.server.host = _ask(
        "Listen address", args.host or config.server.host, non_interactive=non_interactive
    )
    config.server.port = int(
        _ask("Port", str(args.port or config.server.port), non_interactive=non_interactive)
    )
    config.server.workers = int(
        _ask("Workers", str(args.workers or config.server.workers), non_interactive=non_interactive)
    )
    print(
        "\nOnly answer yes if a reverse proxy really sits in front of the service.\n"
        "It makes the service trust X-Forwarded-For, which changes who counts as local."
    )
    config.server.proxy_headers = _ask_yes_no(
        "Behind a reverse proxy?", args.proxy_headers or config.server.proxy_headers,
        non_interactive=non_interactive,
    )

    # 4. Password login over loopback ----------------------------------------
    print(
        "\nPassword sign-in over loopback is the only way a password alone yields a\n"
        "full session. Behind a proxy on the same host every request looks local,\n"
        "which is why this stays off unless you say otherwise."
    )
    config.auth.allow_local_password_login = _ask_yes_no(
        "Allow password sign-in over loopback?",
        args.allow_local_password_login or config.auth.allow_local_password_login,
        non_interactive=non_interactive,
    )

    if not config.secret_key:
        config.secret_key = new_secret_key()

    # 5. Administrator -------------------------------------------------------
    admin_name = _ask("\nName of the administrator", args.admin_name or "admin",
                      non_interactive=non_interactive)
    admin_email = _ask("E-mail", args.admin_email or "", non_interactive=non_interactive)
    password = _ask_password(non_interactive, args.admin_password)

    # 6. Write it out --------------------------------------------------------
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    (VAR_DIR / "vaults").mkdir(exist_ok=True)
    written = config.save(target)

    # Through Alembic, not create_all: otherwise the version table stays empty
    # and the first real migration would try to create tables that already exist.
    db.init(config)
    migrations.upgrade_to_head(config.resolved_database_url())
    with db.session_scope() as session:
        existing = session.query(User).filter_by(name=admin_name).one_or_none()
        if existing is None:
            existing = User(name=admin_name)
            session.add(existing)
        existing.email = admin_email
        existing.password_hash = security.hash_password(password)
        existing.is_admin = True
        existing.is_active = True
        # The password is a bootstrap credential, nothing more: the first
        # session can do nothing except register a passkey.
        existing.must_enroll_passkey = True
        existing.enroll_expires_at = security.enrollment_deadline(config.auth.enrollment_hours)

    print(f"\nConfiguration written: {written}")
    print(f"Database:              {config.resolved_database_url()}")
    print(f"Vault directory:       {VAR_DIR / 'vaults'}")
    print("\nNext:")
    print("  python mmo_vault.py start")
    print(f"  then sign in as '{admin_name}' at {config.auth.origin}")
    print(
        f"\nThe first session can do nothing but register a passkey, and the window\n"
        f"closes after {config.auth.enrollment_hours} hours. Reopen it with:\n"
        f"  python mmo_vault.py enroll {admin_name}"
    )
    return 0


# --------------------------------------------------------------------- start


def cmd_start(args: argparse.Namespace) -> int:
    try:
        config = Config.load(Path(args.config) if args.config else None)
    except ConfigMissing as err:
        print(err, file=sys.stderr)
        return 1

    import uvicorn

    engine = db.init(config)
    if migrations.pending_migrations(engine):
        print(
            "The database schema is out of date.\n"
            "Run `python mmo_vault.py setup --force` or `alembic upgrade head`.",
            file=sys.stderr,
        )
        return 1
    host = args.host or config.server.host
    port = args.port or config.server.port
    print(f"MMO Vault on http://{host}:{port}  (rp_id={config.auth.rp_id})")

    uvicorn.run(
        "mmo_vault.server.app:create_app",
        factory=True,
        host=host,
        port=port,
        # Reload and multiple workers are mutually exclusive; reload also has to
        # keep a single process to hold on to its watcher.
        workers=None if args.reload else config.server.workers,
        reload=args.reload,
        proxy_headers=config.server.proxy_headers,
        forwarded_allow_ips="*" if config.server.proxy_headers else None,
    )
    return 0


# -------------------------------------------------------------------- enroll


def cmd_enroll(args: argparse.Namespace) -> int:
    try:
        config = Config.load(Path(args.config) if args.config else None)
    except ConfigMissing as err:
        print(err, file=sys.stderr)
        return 1

    db.init(config)
    password = args.password or security.generate_password()
    with db.session_scope() as session:
        user = session.query(User).filter_by(name=args.user).one_or_none()
        if user is None:
            print(f"No account named '{args.user}'.", file=sys.stderr)
            return 1
        user.password_hash = security.hash_password(password)
        user.must_enroll_passkey = True
        user.enroll_expires_at = security.enrollment_deadline(config.auth.enrollment_hours)
        user.is_active = True

    print(f"Enrollment reopened for '{args.user}'.")
    print(f"One-time password: {password}")
    print(
        f"Valid for {config.auth.enrollment_hours} hours. The session it grants can do\n"
        "nothing but register a passkey; afterwards the password is discarded."
    )
    return 0


# ----------------------------------------------------------------- arguments


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mmo_vault.py",
        description="MMO Vault - server variant",
    )
    parser.add_argument("--config", help="path to config.toml (default: var/config.toml)")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="interactive first-time setup")
    setup.add_argument("--force", action="store_true", help="change an existing configuration")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--database-url")
    setup.add_argument("--rp-id")
    setup.add_argument("--origin")
    setup.add_argument("--host")
    setup.add_argument("--port", type=int)
    setup.add_argument("--workers", type=int)
    setup.add_argument("--proxy-headers", action="store_true")
    setup.add_argument("--allow-local-password-login", action="store_true")
    setup.add_argument("--admin-name")
    setup.add_argument("--admin-email")
    setup.add_argument("--admin-password")
    setup.set_defaults(func=cmd_setup)

    start = sub.add_parser("start", help="run the service")
    start.add_argument("--host")
    start.add_argument("--port", type=int)
    start.add_argument("--reload", action="store_true", help="for development")
    start.set_defaults(func=cmd_start)

    enroll = sub.add_parser("enroll", help="reopen passkey registration for an account")
    enroll.add_argument("user")
    enroll.add_argument("--password", help="use this one-time password instead of a generated one")
    enroll.set_defaults(func=cmd_enroll)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Everything is relative to the project root, so the service behaves the
    # same no matter which directory it was started from.
    sys.path.insert(0, str(PROJECT_ROOT))
    args = build_parser().parse_args(argv)
    return args.func(args)
