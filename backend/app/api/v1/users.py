"""User management inside the caller's organisation (admin only)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.deps import AdminDep, SessionDep
from app.core.security import hash_password
from app.db.models import User
from app.schemas.auth import UserCreate, UserOut

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(admin: AdminDep, session: SessionDep) -> list[User]:
    rows = await session.execute(
        select(User).where(User.org_id == admin.org_id).order_by(User.email)
    )
    return list(rows.scalars())


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, admin: AdminDep, session: SessionDep) -> User:
    user = User(
        org_id=admin.org_id,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role.value,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from exc
    return user
