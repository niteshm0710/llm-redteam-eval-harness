"""Gateway bearer-token authentication for the FastAPI evaluation service."""

from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer_scheme = HTTPBearer(auto_error=False)


async def require_gateway_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> None:
    """Enforce constant-time Bearer token auth when `REDTEAM_API_TOKEN` is configured."""
    expected_token: str | None = request.app.state.harness.settings.api_token
    if not expected_token:
        return

    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not hmac.compare_digest(
            credentials.credentials.encode("utf-8"), expected_token.encode("utf-8")
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing gateway bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
