"""Delivering the vault application - with two changes, and no more.

The file on disk stays exactly the one that also works offline. Only the copy
that goes over the wire is altered, in two places:

  1. connect-src 'none' becomes connect-src 'self'
  2. an inline script before </body> provides window.mmoVaultServer

That is what keeps the promise intact for the local file: it contains no URL,
no fetch call, and its policy still forbids every connection. The served copy
may talk to its own origin and to nothing else.

Both changes are exact string replacements, and the result is offered in plain
text at /api/injection so anyone can see what was added.

The script has to be inline. The application's policy says
`script-src 'unsafe-inline'` and nothing else - an external <script src> would
be blocked by the very policy this file is careful not to widen.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .environment import PROJECT_ROOT

APP_PATH = PROJECT_ROOT / "mmo_vault" / "public_html" / "mmo_vault.html"
ADAPTER_PATH = Path(__file__).resolve().parent / "static" / "server.js"

CSP_FROM = "connect-src 'none'"
CSP_TO = "connect-src 'self'"
# The adapter goes BEFORE the application's own script, not at the end of
# the document. The application asks for window.mmoVaultServer while it
# starts up; an adapter that registers itself afterwards arrives too late,
# and the vault list stays empty with nothing to explain why.
APP_SCRIPT = "<script>"


class InjectionFailed(RuntimeError):
    """The application file does not look the way it has to.

    Raised loudly rather than served silently: an application delivered without
    the adapter would show an empty vault list and no reason for it.
    """


@dataclass
class Injected:
    html: str
    script: str
    # Both source files, so the cache can tell when either changed.
    signature: tuple[float, int, float, int]


_cache: Injected | None = None


def _signature() -> tuple[float, int, float, int]:
    app = APP_PATH.stat()
    adapter = ADAPTER_PATH.stat()
    return (app.st_mtime, app.st_size, adapter.st_mtime, adapter.st_size)


def adapter_source() -> str:
    return ADAPTER_PATH.read_text(encoding="utf-8")


def build() -> Injected:
    html = APP_PATH.read_text(encoding="utf-8")
    if html.count(CSP_FROM) != 1:
        raise InjectionFailed(
            f"expected exactly one {CSP_FROM!r} in the application file"
        )
    if html.count(APP_SCRIPT) != 1:
        raise InjectionFailed("expected exactly one <script> in the application file")

    script = adapter_source()
    html = html.replace(CSP_FROM, CSP_TO)
    html = html.replace(
        APP_SCRIPT, f"<script>\n{script}\n</script>\n{APP_SCRIPT}", 1
    )
    return Injected(html=html, script=script, signature=_signature())


def render() -> Injected:
    """Cached, but rebuilt when either source file changes.

    Matters during development, and does no harm in production: the check is
    two stat() calls.
    """
    global _cache
    if _cache is None or _cache.signature != _signature():
        _cache = build()
    return _cache
