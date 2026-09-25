from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from forensic.report_models import EvidenceMetadata


def calculate_sha256(raw_data: bytes) -> str:
    return hashlib.sha256(raw_data).hexdigest()


def create_evidence_metadata(
    email_id: str,
    raw_data: bytes,
    captured_by: str = "system",
    source: str | None = None,
    original_filename: str | None = None,
) -> EvidenceMetadata:
    return EvidenceMetadata(
        evidence_id=f"evidence-{email_id}",
        email_id=email_id,
        sha256=calculate_sha256(raw_data),
        captured_at=datetime.now(timezone.utc),
        captured_by=captured_by,
        source=source,
        original_filename=original_filename,
        content_length=len(raw_data),
    )

