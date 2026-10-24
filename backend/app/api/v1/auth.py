"""Registration, login and identity."""

from __future__ import annotations

from functools import lru_cache

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.deps import PrincipalDep, SessionDep
from app.core.enums import Role
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import Organization, User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@lru_cache
def _dummy_hash() -> str:
    # Verified against when the email is unknown, so login timing does not reveal accounts.
    return hash_password("not-a-real-password")


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, session: SessionDep) -> TokenResponse:
    """Create an organisation and its first (admin) user."""
    if not get_settings().allow_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Registration is disabled")
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
async def login(body: LoginRequest, session: SessionDep) -> TokenResponse:
    user = (
        await session.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    ok = verify_password(user.password_hash if user else _dummy_hash(), body.password)
    if user is None or not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    return TokenResponse(
        access_token=create_access_token(user.id), user=UserOut.model_validate(user)
    )


@router.get("/me", response_model=UserOut)
async def me(principal: PrincipalDep, session: SessionDep) -> User:
    user = await session.get(User, principal.user_id)
    if user is None:  # deleted between token check and this read
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user
