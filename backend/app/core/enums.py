"""Closed vocabularies shared by the DB constraints, schemas and services."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class SourceMethod(StrEnum):
    NETFLOW = "netflow"
    SENSOR = "sensor"
    HTTP = "http"
    SYSLOG = "syslog"
    SCAN = "scan"  # disabled until ownership attestation + audit log exist (ADR-006)


class SourceStatus(StrEnum):
    PENDING = "pending"  # registered, no flows seen yet
    ACTIVE = "active"


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class Severity(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


def sql_in(values: type[StrEnum]) -> str:
    """Render ``'a', 'b'`` for CHECK constraints."""
    return ", ".join(f"'{v.value}'" for v in values)
