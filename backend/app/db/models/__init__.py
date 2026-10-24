"""Importing this package registers every table on ``Base.metadata``."""

from app.db.models.alerts import Alert, Recommendation
from app.db.models.flows import flows, predictions
from app.db.models.reference import EvaluationResponse, ModelRegistry, RiskSnapshot, Vulnerability
from app.db.models.sources import Asset, Source
from app.db.models.tenancy import Organization, User

__all__ = [
    "Alert",
    "Asset",
    "EvaluationResponse",
    "ModelRegistry",
    "Organization",
    "Recommendation",
    "RiskSnapshot",
    "Source",
    "User",
    "Vulnerability",
    "flows",
    "predictions",
]
