"""
Tests for the DatasetSeeder module.

Verifies that:
1. Each _seed_* function correctly reads its bundled CSV/JSON.
2. No errors are raised when called in dry_run=True mode.
3. In real mode (no dry_run), storage functions are called with non-empty data.
4. seed_all() returns a dict with all four scenario keys.
5. validate() returns True for all four files.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Make sure the project root is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Stubs for heavy dependencies that dataset_seeder imports
# ---------------------------------------------------------------------------

def _make_stub_module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    return mod


@pytest.fixture(autouse=True)
def stub_dependencies(monkeypatch):
    """Stub storage, detectors, and api.logging_utils so the seeder can be
    imported and tested without a live Redis instance or FastAPI app."""

    # --- api.logging_utils stub ---
    lu = _make_stub_module("api.logging_utils")
    lu.logfmt = lambda event, **kw: f"{event} {kw}"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "api", _make_stub_module("api"))
    monkeypatch.setitem(sys.modules, "api.logging_utils", lu)

    # --- storage stub ---
    storage_mod = _make_stub_module("storage")
    storage_mod.add_flagged_intelligence = MagicMock()  # type: ignore[attr-defined]
    storage_mod.add_pheromone = MagicMock()             # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "storage", storage_mod)

    # --- detectors stub ---
    detectors_mod = _make_stub_module("detectors")
    detectors_mod.run_detectors = MagicMock(return_value={"total_delta": 0, "signals": []})  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "detectors", detectors_mod)

    yield storage_mod, detectors_mod


# ---------------------------------------------------------------------------
# Import the module AFTER stubs are in place
# ---------------------------------------------------------------------------

@pytest.fixture()
def seeder(stub_dependencies):
    # Re-import fresh after stubs applied
    import importlib
    import dataset_seeder as ds
    importlib.reload(ds)
    return ds


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidate:
    def test_all_files_present(self, seeder):
        results = seeder.dataset_seeder.validate()
        missing = [k for k, v in results.items() if not v]
        assert missing == [], f"Missing dataset files: {missing}"


class TestSeedPhishingC2:
    def test_dry_run_returns_counts(self, seeder, stub_dependencies):
        storage_mod, _ = stub_dependencies
        result = seeder._seed_phishing_c2(dry_run=True)
        assert result["phishing_links"] > 0, "Expected phishing links from CIC-IDS CSV"
        assert result["attacker_ips"] > 0,   "Expected attacker IPs from CIC-IDS CSV"
        storage_mod.add_flagged_intelligence.assert_not_called()
        storage_mod.add_pheromone.assert_not_called()

    def test_real_mode_calls_storage(self, seeder, stub_dependencies):
        storage_mod, _ = stub_dependencies
        seeder._seed_phishing_c2(dry_run=False)
        storage_mod.add_flagged_intelligence.assert_called_once()
        call_kwargs = storage_mod.add_flagged_intelligence.call_args[1]
        assert len(call_kwargs.get("phishing_links", [])) > 0
        assert storage_mod.add_pheromone.call_count > 0


class TestSeedAccountTakeover:
    def test_dry_run_returns_counts(self, seeder, stub_dependencies):
        storage_mod, _ = stub_dependencies
        result = seeder._seed_account_takeover(dry_run=True)
        assert result["users_seeded"] > 0, "Expected users from SecRepo CSV"
        assert result["ips_seeded"] > 0,   "Expected IPs from SecRepo CSV"
        storage_mod.add_pheromone.assert_not_called()

    def test_real_mode_calls_pheromone(self, seeder, stub_dependencies):
        storage_mod, _ = stub_dependencies
        seeder._seed_account_takeover(dry_run=False)
        assert storage_mod.add_pheromone.call_count > 0


class TestSeedPaymentFraud:
    def test_dry_run_returns_counts(self, seeder, stub_dependencies):
        storage_mod, _ = stub_dependencies
        result = seeder._seed_payment_fraud(dry_run=True)
        assert result["fraud_tx_ids"] > 0, "Expected fraud transaction IDs from UNSW-NB15 CSV"
        storage_mod.add_flagged_intelligence.assert_not_called()

    def test_real_mode_seeds_upi_ids(self, seeder, stub_dependencies):
        storage_mod, _ = stub_dependencies
        seeder._seed_payment_fraud(dry_run=False)
        storage_mod.add_flagged_intelligence.assert_called_once()
        call_kwargs = storage_mod.add_flagged_intelligence.call_args[1]
        assert len(call_kwargs.get("upi_ids", [])) > 0


class TestSeedBenignBaseline:
    def test_dry_run_no_detector_calls(self, seeder, stub_dependencies):
        _, detectors_mod = stub_dependencies
        result = seeder._seed_benign_baseline(dry_run=True)
        assert result["baseline_events"] == 0  # dry_run returns 0 (skips processing)
        detectors_mod.run_detectors.assert_not_called()

    def test_real_mode_warms_detectors(self, seeder, stub_dependencies):
        _, detectors_mod = stub_dependencies
        result = seeder._seed_benign_baseline(dry_run=False)
        assert result["baseline_events"] > 0
        assert detectors_mod.run_detectors.call_count > 0


class TestSeedAll:
    def test_returns_all_four_scenario_keys(self, seeder):
        result = seeder.seed_all(dry_run=True)
        assert "scenario1_phishing_c2" in result
        assert "scenario2_account_takeover" in result
        assert "scenario3_payment_fraud" in result
        assert "scenario4_benign_baseline" in result

    def test_no_errors_on_full_run(self, seeder, stub_dependencies):
        """seed_all() must not raise even if individual seeders fail."""
        result = seeder.seed_all(dry_run=False)
        for key, val in result.items():
            assert "error" not in val, f"{key} failed: {val}"
