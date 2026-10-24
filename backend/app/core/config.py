"""Application settings, read from environment variables (see .env.example)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_SECRET_PREFIX = "dev-only"  # noqa: S105 - marker, not a credential


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"

    database_url: str
    redis_url: str

    secret_key: SecretStr
    access_token_minutes: int = 60
    allow_registration: bool = True  # open org sign-up; disable on a public deployment

    # What the onboarding wizard tells users to point their router at.
    collector_public_host: str = "localhost"
    collector_public_port: int = 2055
    api_public_url: str = "http://localhost:8000"

    # Ingestion
    max_batch_flows: int = 5000
    stream_flows: str = "flows.raw"
    stream_dead: str = "flows.dead"
    stream_group: str = "workers"
    stream_maxlen: int = 500_000
    worker_batch_size: int = 500
    worker_block_ms: int = 1000
    worker_reclaim_idle_ms: int = 60_000

    # Alerting (placeholder-classifier era; revisited with the real model in Phase 2/4)
    alert_min_probability: float = 0.7
    alert_min_flows: int = 5
    alert_window_seconds: int = 60
    alert_merge_seconds: int = 300

    # Privacy
    pseudonymize_ips: bool = False
    pseudonym_key: SecretStr = SecretStr("dev-only-pseudonym-key")

    # Demo seed (dev convenience only; never enable in prod)
    seed_demo_data: bool = False
    demo_password: SecretStr = SecretStr("dev-only-demo-password")
    demo_api_key: SecretStr = SecretStr("sbi_demo_dev_only_api_key_0000000000000000")

    @model_validator(mode="after")
    def _refuse_insecure_prod(self) -> Settings:
        if self.env == "prod":
            problems = []
            secret = self.secret_key.get_secret_value()
            if secret.startswith(INSECURE_SECRET_PREFIX) or len(secret) < 32:
                problems.append("SECRET_KEY must be set to a random value of >= 32 chars")
            if self.pseudonym_key.get_secret_value().startswith(INSECURE_SECRET_PREFIX):
                problems.append("PSEUDONYM_KEY must be set in prod")
            if self.seed_demo_data:
                problems.append("SEED_DEMO_DATA must be false in prod")
            if problems:
                raise ValueError("; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # required fields come from the environment
