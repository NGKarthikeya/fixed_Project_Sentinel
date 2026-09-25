import os
os.environ.setdefault("API_KEY", "dev-secret-key")
os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = "true"

import storage
from demo.run_scenarios import run_all_scenarios
import asyncio


def setup_function():
    from config import config
    config.dataset_seed_on_startup = False
    storage.reset_runtime_state()
    storage._redis_available = lambda: False


def test_demo_runner_generates_metrics_and_audits():
    summary = asyncio.run(run_all_scenarios())

    assert summary["scenario_count"] == 4
    assert summary["detection_rate"] >= 0.66
    assert summary["fp_rate"] <= 0.25
    assert summary["output_path"].endswith("latest_metrics.json")

    positive_results = [r for r in summary["results"] if r["expected_positive"]]
    assert any(result["audit_count"] > 0 for result in positive_results)
