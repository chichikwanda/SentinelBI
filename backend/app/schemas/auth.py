"""Auth and user schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.enums import Role

_PASSWORD = Field(min_length=10, max_length=128)


class RegisterRequest(BaseModel):
    org_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = _PASSWORD

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class UserCreate(BaseModel):
    email: EmailStr
    password: str = _PASSWORD
    role: Role = Role.VIEWER

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    role: Role


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    user: UserOut
