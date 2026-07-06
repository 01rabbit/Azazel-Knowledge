"""Per-request audit middleware (design S7).

Appends one redacted JSONL line per request to the process's
`AuditChain`: method, path, resolved client `key_id` (parsed from the
bearer token without a DB round trip, so it is available even for
401/403 responses), status code, and duration. The `Authorization`
header itself is never read into the event -- only the token's
`key_id` half is extracted -- and `AuditChain.append` additionally runs
every event through the `SecretRegistry` redactor before it touches
disk. A failure to append here never fails the request (context has
its own fail-closed append on the request thread for the advisory
line, per F-17); it only ever affects `audit_writer_ok` in `/v1/health`.
"""

from __future__ import annotations

import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from azazel_cti.audit.logger import AuditUnavailable
from azazel_cti.security.auth import InvalidToken, parse_token


def _client_key_id(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header[len("Bearer ") :].strip()
    try:
        key_id, _secret = parse_token(token)
    except InvalidToken:
        return None
    return key_id


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.monotonic()
        key_id = _client_key_id(request)
        try:
            response = await call_next(request)
        except Exception:
            self._audit(request, key_id, 500, start)
            raise
        self._audit(request, key_id, response.status_code, start)
        return response

    def _audit(self, request: Request, key_id: str | None, status: int, start: float) -> None:
        audit = getattr(request.app.state, "audit", None)
        if audit is None:
            return
        event = {
            "type": "request",
            "method": request.method,
            "path": request.url.path,
            "key_id": key_id,
            "status": status,
            "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
        }
        try:
            audit.append(event)
        except AuditUnavailable:
            pass
