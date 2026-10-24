"""Password hashing, JWT access tokens and API keys."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.core.config import get_settings

_hasher = PasswordHasher()
_JWT_ALG = "HS256"
API_KEY_PREFIX = "sbi_"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """True only for a correct password.

    Only a genuine mismatch (or an unreadable stored hash) means "wrong password". Any other
    argon2 failure, e.g. it could not allocate its 64 MiB of working memory under load, is
    re-raised (HTTP 500) instead of being reported to the user as bad credentials.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_access_token(user_id: uuid.UUID) -> str:
    """Token carries only the subject; role/org are re-read from the DB on every request,
    so role changes and removals take effect immediately."""
    settings = get_settings()
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(claims, settings.secret_key.get_secret_value(), algorithm=_JWT_ALG)


def decode_access_token(token: str) -> uuid.UUID:
    """Return the user id, or raise ``jwt.InvalidTokenError`` / ``ValueError``."""
    claims = jwt.decode(
        token,
        get_settings().secret_key.get_secret_value(),
        algorithms=[_JWT_ALG],
        options={"require": ["exp", "sub"]},
    )
    return uuid.UUID(claims["sub"])


def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """SHA-256 is right for 256-bit random keys (ADR-010); passwords use argon2."""
    return hashlib.sha256(key.encode()).hexdigest()
