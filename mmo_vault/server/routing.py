"""The route class that owns a request's unit of work.

FastAPI closes the `get_db` dependency - and with it commits the transaction -
only once the response has left the process. That is late enough to be wrong: a
browser following a redirect can issue its next request before the write behind
the previous one is visible to another connection. The sign-in showed it most
plainly, where the freshly written session row was still uncommitted when the
redirect target asked for it, and only a reload got the person in.

Committing from the route handler puts the write back inside the request: the
answer is transmitted only once the transaction is durable. A handler that
raises never reaches the commit, so `session_scope` still rolls back exactly as
it did before.
"""

from __future__ import annotations

from typing import Any, Callable, Coroutine

from fastapi import Request, Response
from fastapi.routing import APIRoute


class UnitOfWork(APIRoute):
    """An APIRoute that commits before it hands its response on."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def commit_then_answer(request: Request) -> Response:
            response = await handler(request)
            # Absent on the routes that never asked for a database session.
            session = getattr(request.state, "db", None)
            if session is not None:
                session.commit()
            return response

        return commit_then_answer
