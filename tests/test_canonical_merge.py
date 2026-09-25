"""Regression coverage for integrations introduced during project consolidation."""

from config import AppConfig
from forensic.report_models import EvidenceMetadata
from storage import (
    get_email_analysis,
    get_evidence_metadata,
    reset_runtime_state,
    save_email_analysis,
    save_evidence_metadata,
)


def test_merged_forensic_storage_round_trip():
    reset_runtime_state()
    evidence = EvidenceMetadata(
        evidence_id="evidence-merge-test-1",
        email_id="merge-test-1",
        sha256="a" * 64,
        captured_at="2026-01-01T00:00:00Z",
    )
    save_evidence_metadata("merge-test-1", evidence)
    save_email_analysis("merge-test-1", {"is_scam": True})

    assert get_evidence_metadata("merge-test-1").email_id == "merge-test-1"
    assert get_email_analysis("merge-test-1") == {"is_scam": True}


def test_merged_config_bounds_invalid_numbers(monkeypatch):
    monkeypatch.setenv("API_KEY", "real-secret-value")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "invalid")
    monkeypatch.setenv("CORRELATION_THRESHOLD", "1000")

    cfg = AppConfig.from_env()

    assert cfg.api.rate_limit_requests == 30
    assert cfg.correlation.create_threshold == 100.0
