"""FastAPI dependencies: sessions, current user, role checks, API-key auth.

Every dependency that identifies a caller returns an ``org_id`` that route handlers MUST use
to scope queries (design rule 1).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role
from app.core.security import decode_access_token, hash_api_key
from app.db.models import Source, User
from app.db.session import get_session

SessionDep = Annotated[AsyncSession, Depends(get_session)]
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    org_id: uuid.UUID
    email: str
    role: Role


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def current_principal(
    session: SessionDep,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if creds is None:
        raise _unauthorized()
    try:
        user_id = decode_access_token(creds.credentials)
    except (jwt.InvalidTokenError, ValueError) as exc:
        raise _unauthorized() from exc
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise _unauthorized()
    return Principal(user.id, user.org_id, user.email, Role(user.role))


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def require_role(*allowed: Role) -> Callable[..., Coroutine[Any, Any, Principal]]:
    """Dependency factory: 403 unless the caller holds one of ``allowed``."""

    async def _check(principal: PrincipalDep) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return principal

    return _check


AdminDep = Annotated[Principal, Depends(require_role(Role.ADMIN))]
AnalystDep = Annotated[Principal, Depends(require_role(Role.ADMIN, Role.ANALYST))]


async def source_by_api_key(
    session: SessionDep,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Source:
    if not x_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key")
    source = (
        await session.execute(select(Source).where(Source.api_key_hash == hash_api_key(x_api_key)))
    ).scalar_one_or_none()
    if source is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    return source


SourceDep = Annotated[Source, Depends(source_by_api_key)]
