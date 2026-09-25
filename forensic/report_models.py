from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class EvidenceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    email_id: str = Field(min_length=1, max_length=128)
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    captured_at: datetime
    captured_by: str = Field(default="system", max_length=128)
    source: str | None = Field(default=None, max_length=256)
    original_filename: str | None = Field(default=None, max_length=256)
    content_length: int | None = Field(default=None, ge=0)
    hash_algorithm: str = "SHA-256"
    integrity_status: str = "verified"


class ForensicReportContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: str
    email_id: str
    generated_at: datetime
    generator_version: str
    risk_score: float = Field(ge=0, le=100)
    risk_level: str
    verdict: str
    evidence: EvidenceMetadata
    sender: dict
    authentication: dict
    headers: dict
    origin_trace: dict | None = None
    domain_intel: dict | None = None
    indicators: list[dict] = Field(default_factory=list)
    mitre_matches: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

