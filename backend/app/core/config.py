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
    redis_timeout_seconds: float = 30.0  # how long one Redis command may take before it fails

    secret_key: SecretStr
    access_token_minutes: int = 60
    allow_registration: bool = True  # open org sign-up; disable on a public deployment
    # sign-in: this many FAILED attempts on one account lock it for the window (a success resets it)
    login_max_failures: int = 8
    login_lockout_seconds: int = 900
    # open sign-up: at most this many organisations per hour across the whole deployment
    register_max_per_hour: int = 20

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
    # Alert work is per source and class per batch, not per flow, so bigger batches are cheaper per
    # flow: on attack-heavy replay traffic one worker drained 786 flows/s at 500, 1,441 at 2,000.
    # Under light load a batch is just whatever has arrived, so latency does not grow.
    worker_batch_size: int = 2000
    worker_block_ms: int = 1000
    worker_reclaim_idle_ms: int = 60_000

    # Alerting (placeholder-classifier era; revisited with the real model in Phase 2/4)
    alert_min_probability: float = 0.7
    # a source's flagged flows must also be at least this share of ALL its flows in the window,
    # so a busy benign host with a ~1% false-positive rate does not raise alerts
    alert_min_share: float = 0.2
    alert_min_flows: int = 5
    alert_window_seconds: int = 60
    alert_merge_seconds: int = 300

    # Baseline and quarantine. A source learns which devices and networks are normal for this many
    # days; after that, anything new waits for a decision. A High or Critical alert flags the
    # address it came from and holds it for a decision (nothing on the network is blocked by us).
    baseline_days: int = 7
    auto_quarantine: bool = True
    quarantine_min_severity: str = "High"

    # Models and risk
    models_dir: str = "/repo/ml/models"
    # datasets live in <data_dir>/raw (the trainer writes them, the API only looks)
    data_dir: str = "/repo/data"
    # backups made from the web interface (the trainer writes them, the API lists them)
    backups_dir: str = "/repo/backups"
    # the sensor script handed out to users; mounted read-only into the API container
    sensor_script_path: str = "/repo/sensor/sentinelbi_sensor.py"
    model_refresh_seconds: int = 30
    risk_snapshot_seconds: int = 60
    risk_decay_half_life_hours: float = 6.0
    # comma-separated emails allowed to switch the PLATFORM-WIDE active model
    platform_admin_emails: str = ""

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
            if "demo.sentinelbi.example" in self.platform_admin_emails:
                problems.append("PLATFORM_ADMIN_EMAILS must not contain the demo account in prod")
            if self.seed_demo_data:
                problems.append("SEED_DEMO_DATA must be false in prod")
            if problems:
                raise ValueError("; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # required fields come from the environment
