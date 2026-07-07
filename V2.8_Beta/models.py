"""Shared data models for the ASVP platform."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class OwaspCategory(str, Enum):
    A01_ACCESS_CONTROL       = "A01:broken_access_control"
    A02_MISCONFIGURATION     = "A02:security_misconfiguration"
    A03_SUPPLY_CHAIN         = "A03:software_supply_chain_failures"
    A04_CRYPTO_FAILURES      = "A04:cryptographic_failures"
    A05_INJECTION            = "A05:injection"
    A06_INSECURE_DESIGN      = "A06:insecure_design"
    A07_AUTH_FAILURES        = "A07:authentication_failures"
    A08_INTEGRITY_FAILURES   = "A08:software_data_integrity_failures"
    A09_LOGGING_FAILURES     = "A09:logging_alerting_failures"
    A10_EXCEPTIONAL          = "A10:mishandling_exceptional_conditions"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ValidationStatus(str, Enum):
    POTENTIAL = "potential"   # single source, unconfirmed
    LIKELY    = "likely"      # 2 sources or strong single-source evidence
    CONFIRMED = "confirmed"   # 3+ sources or AI-confirmed exploitable


class RemediationStatus(str, Enum):
    OPEN                 = "open"
    IN_PROGRESS          = "in_progress"
    READY_FOR_VALIDATION = "ready_for_validation"
    REMEDIATED           = "remediated"
    REOPENED             = "reopened"


class RawFinding(BaseModel):
    """A finding straight out of a scanner, before correlation or triage."""
    id: Optional[int] = None  # set when read back from the pending queue
    tool: str
    category: OwaspCategory
    title: str
    url: Optional[str] = None
    app_name: Optional[str] = None
    raw_severity: Optional[str] = None
    description: str = ""
    evidence: str = ""


class TriagedFinding(BaseModel):
    """A fully-analyzed finding after correlation and AI triage."""
    id: Optional[int] = None

    # Identity
    app_name: str = "unspecified"
    url: Optional[str] = None
    vulnerability_name: str = ""
    tool: str = ""                 # primary detecting tool (hidden from UI)

    # Classification
    category: OwaspCategory
    cwe_id: str = ""               # e.g. "CWE-89"
    cwe_name: str = ""             # e.g. "Improper Neutralization of SQL Commands"
    vulnerable_parameter: Optional[str] = None  # e.g. "username", "id", "X-Forwarded-For"

    # Risk scoring
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # Confidence and validation
    confidence: int = 0            # 0-100
    validation_status: ValidationStatus = ValidationStatus.POTENTIAL
    source_count: int = 1          # how many independent scanners detected this
    exploitable: bool = False

    # Full analysis sections
    rationale: str = ""
    root_cause: Optional[str] = None
    attack_scenario: Optional[str] = None
    technical_impact: Optional[str] = None
    business_impact: Optional[str] = None
    reproduction_steps: Optional[str] = None
    evidence_summary: Optional[str] = None
    remediation: Optional[str] = None

    # Lifecycle
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    remediation_notes: Optional[str] = None

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None


class AttackChain(BaseModel):
    """A correlated multi-step attack path across findings."""
    id: Optional[int] = None
    app_name: str
    chain_name: str
    risk_score: float              # 0-10
    exploitation_difficulty: str   # easy / medium / hard
    preconditions: str = ""
    attack_flow: str = ""          # step-by-step narrative
    business_impact: str = ""
    mitigations: str = ""
    finding_ids: List[int] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
