"""Idempotent demo seed: one organisation with three users, a source, assets and the
placeholder model registry row. Dev/demo only; refuses to run when ENV=prod (ADR-009).

    python -m app.db.seed
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import Role, SourceMethod, SourceStatus
from app.core.logging import configure_logging
from app.core.security import hash_api_key, hash_password
from app.db.models import Asset, ModelRegistry, Organization, Source, User
from app.db.session import get_engine, get_sessionmaker
from app.services.inference.placeholder import PLACEHOLDER_VERSION
from sentinelbi_ml.features import CORE_FEATURES

log = logging.getLogger("seed")

DEMO_ORG = "Demo ICT SME (Harare)"
DEMO_DOMAIN = "demo.sentinelbi.example"  # .local/.test are rejected by email validation
DEMO_SOURCE_NAME = "Demo office network (replay)"
DEMO_CIDR = "10.20.0.0/24"
DEMO_ASSETS = [
    # ip, hostname, criticality (1 low .. 3 high), internet_facing
    ("10.20.0.10", "mail-server", 3, True),
    ("10.20.0.20", "web-server", 3, True),
    ("10.20.0.50", "workstation-01", 1, False),
]


async def seed(session: AsyncSession) -> dict[str, str]:
    settings = get_settings()
    if settings.env == "prod":
        raise RuntimeError("refusing to seed demo data when ENV=prod")

    org = (
        await session.execute(select(Organization).where(Organization.name == DEMO_ORG))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name=DEMO_ORG)
        session.add(org)
        await session.flush()

    password_hash = hash_password(settings.demo_password.get_secret_value())
    for role in Role:
        email = f"{role.value}@{DEMO_DOMAIN}"
        exists = (await session.execute(select(User.id).where(User.email == email))).first()
        if exists is None:
            session.add(
                User(org_id=org.id, email=email, password_hash=password_hash, role=role.value)
            )

    key_hash = hash_api_key(settings.demo_api_key.get_secret_value())
    source = (
        await session.execute(select(Source).where(Source.api_key_hash == key_hash))
    ).scalar_one_or_none()
    if source is None:
        source = Source(
            org_id=org.id,
            name=DEMO_SOURCE_NAME,
            cidr=DEMO_CIDR,
            method=SourceMethod.HTTP.value,
            api_key_hash=key_hash,
            status=SourceStatus.PENDING.value,
            criticality=2,
        )
        session.add(source)
        await session.flush()
        for ip, hostname, criticality, facing in DEMO_ASSETS:
            session.add(
                Asset(
                    org_id=org.id,
                    source_id=source.id,
                    ip=ip,
                    hostname=hostname,
                    criticality=criticality,
                    internet_facing=facing,
                )
            )

    if await session.get(ModelRegistry, PLACEHOLDER_VERSION) is None:
        has_active = (
            await session.execute(select(ModelRegistry.version).where(ModelRegistry.active))
        ).first()
        session.add(
            ModelRegistry(
                version=PLACEHOLDER_VERSION,
                algo="heuristic-rules (NOT a trained model)",
                metrics={},
                features=list(CORE_FEATURES),
                dataset=None,
                active=has_active is None,
            )
        )
    await session.commit()
    return {
        "org": DEMO_ORG,
        "users": f"{{admin,analyst,viewer}}@{DEMO_DOMAIN}",
        "source": DEMO_SOURCE_NAME,
    }


async def main() -> None:
    configure_logging(get_settings().log_level)
    async with get_sessionmaker()() as session:
        summary = await seed(session)
    await get_engine().dispose()
    log.info(
        "demo seed ready: %s (passwords/API key come from DEMO_PASSWORD / DEMO_API_KEY)", summary
    )


if __name__ == "__main__":
    asyncio.run(main())
