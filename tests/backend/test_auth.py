from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import jwt
from conftest import PASSWORD, register_org, unique_email

from app.core.config import Settings


async def test_register_creates_org_and_admin(client: httpx.AsyncClient) -> None:
    email = unique_email("owner")
    resp = await client.post(
        "/api/v1/auth/register",
        json={"org_name": "Zim Tech", "email": email.upper(), "password": PASSWORD},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "admin"
    assert body["user"]["email"] == email  # normalised to lower case

    me = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["org_id"] == body["user"]["org_id"]


async def test_duplicate_email_is_rejected(client: httpx.AsyncClient) -> None:
    t = await register_org(client)
    resp = await client.post(
        "/api/v1/auth/register", json={"org_name": "Other", "email": t.email, "password": PASSWORD}
    )
    assert resp.status_code == 409


async def test_weak_password_is_rejected(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"org_name": "Zim Tech", "email": unique_email(), "password": "short"},
    )
    assert resp.status_code == 422


async def test_login_success_and_failures(client: httpx.AsyncClient) -> None:
    t = await register_org(client)
    ok = await client.post("/api/v1/auth/login", json={"email": t.email, "password": PASSWORD})
    assert ok.status_code == 200
    assert ok.json()["access_token"]

    wrong = await client.post(
        "/api/v1/auth/login", json={"email": t.email, "password": "wrong-password-1"}
    )
    unknown = await client.post(
        "/api/v1/auth/login", json={"email": unique_email("ghost"), "password": PASSWORD}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # no account enumeration


async def test_protected_routes_reject_missing_or_bad_tokens(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    assert (await client.get("/api/v1/sources")).status_code == 401
    assert (
        await client.get("/api/v1/sources", headers={"Authorization": "Bearer garbage"})
    ).status_code == 401

    secret = settings.secret_key.get_secret_value()
    expired = jwt.encode(
        {"sub": str(uuid.uuid4()), "exp": datetime.now(UTC) - timedelta(minutes=1)},
        secret,
        algorithm="HS256",
    )
    assert (
        await client.get("/api/v1/sources", headers={"Authorization": f"Bearer {expired}"})
    ).status_code == 401

    wrong_key = jwt.encode(
        {"sub": str(uuid.uuid4()), "exp": datetime.now(UTC) + timedelta(minutes=5)},
        "x" * 40,
        algorithm="HS256",
    )
    assert (
        await client.get("/api/v1/sources", headers={"Authorization": f"Bearer {wrong_key}"})
    ).status_code == 401

    # valid signature but the user does not exist (deleted account)
    ghost = jwt.encode(
        {"sub": str(uuid.uuid4()), "exp": datetime.now(UTC) + timedelta(minutes=5)},
        secret,
        algorithm="HS256",
    )
    assert (
        await client.get("/api/v1/sources", headers={"Authorization": f"Bearer {ghost}"})
    ).status_code == 401


async def test_registration_can_be_disabled(
    client: httpx.AsyncClient, settings: Settings, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(settings, "allow_registration", False)
    resp = await client.post(
        "/api/v1/auth/register",
        json={"org_name": "Zim Tech", "email": unique_email(), "password": PASSWORD},
    )
    assert resp.status_code == 403


async def test_roles_admin_manages_users_others_cannot(client: httpx.AsyncClient) -> None:
    admin = await register_org(client)
    analyst_email, viewer_email = unique_email("analyst"), unique_email("viewer")
    for email, role in ((analyst_email, "analyst"), (viewer_email, "viewer")):
        r = await client.post(
            "/api/v1/users",
            json={"email": email, "password": PASSWORD, "role": role},
            headers=admin.headers,
        )
        assert r.status_code == 201, r.text
        assert r.json()["org_id"] == admin.org_id  # created inside the admin's own org

    tokens = {}
    for email in (analyst_email, viewer_email):
        r = await client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        tokens[email] = {"Authorization": f"Bearer {r.json()['access_token']}"}

    new_user = {"email": unique_email(), "password": PASSWORD, "role": "viewer"}
    source = {"name": "HQ", "cidr": "10.0.0.0/24", "method": "http"}
    for email in (analyst_email, viewer_email):
        assert (
            await client.post("/api/v1/users", json=new_user, headers=tokens[email])
        ).status_code == 403
        assert (await client.get("/api/v1/users", headers=tokens[email])).status_code == 403
        assert (
            await client.post("/api/v1/sources", json=source, headers=tokens[email])
        ).status_code == 403
        # but both can read
        assert (await client.get("/api/v1/sources", headers=tokens[email])).status_code == 200

    listed = await client.get("/api/v1/users", headers=admin.headers)
    assert {u["email"] for u in listed.json()} == {admin.email, analyst_email, viewer_email}
