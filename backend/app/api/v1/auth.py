"""Registration, login and identity."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.deps import PrincipalDep, SessionDep
from app.core.enums import Role
from app.core.ratelimit import clear, minutes, record_hit, seconds_until_allowed
from app.core.redis import get_redis
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import Organization, User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

RedisDep = Annotated[Redis, Depends(get_redis)]


def _too_many(wait: int, what: str) -> HTTPException:
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"Too many {what}. Try again in {minutes(wait)} minute(s).",
        headers={"Retry-After": str(wait)},
    )


@lru_cache
def _dummy_hash() -> str:
    # Verified against when the email is unknown, so login timing does not reveal accounts.
    return hash_password("not-a-real-password")


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, session: SessionDep, redis: RedisDep) -> TokenResponse:
    """Create an organisation and its first (admin) user."""
    if not get_settings().allow_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Registration is disabled")
    settings = get_settings()
    wait = await seconds_until_allowed(redis, "register", "all", settings.register_max_per_hour)
    if wait:
        raise _too_many(wait, "sign-ups")
    await record_hit(redis, "register", "all", 3600)
    org = Organization(name=body.org_name)
    session.add(org)
    await session.flush()
    user = User(
        org_id=org.id,
        email=body.email,
        password_hash=hash_password(body.password),
        role=Role.ADMIN.value,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from exc
    return TokenResponse(
        access_token=create_access_token(user.id), user=UserOut.model_validate(user)
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, session: SessionDep, redis: RedisDep) -> TokenResponse:
    settings = get_settings()
    # checked before the password, so a locked account cannot be guessed at while it is locked
    wait = await seconds_until_allowed(redis, "login-fail", body.email, settings.login_max_failures)
    if wait:
        raise _too_many(wait, "failed sign-in attempts")
    user = (
        await session.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    ok = verify_password(user.password_hash if user else _dummy_hash(), body.password)
    if user is None or not ok:
        # unknown addresses are counted too, so the limiter does not reveal which accounts exist
        await record_hit(redis, "login-fail", body.email, settings.login_lockout_seconds)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    await clear(redis, "login-fail", body.email)
    return TokenResponse(
        access_token=create_access_token(user.id), user=UserOut.model_validate(user)
    )


@router.get("/me", response_model=UserOut)
async def me(principal: PrincipalDep, session: SessionDep) -> User:
    user = await session.get(User, principal.user_id)
    if user is None:  # deleted between token check and this read
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user
