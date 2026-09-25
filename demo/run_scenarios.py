"""Local demo scenario runner with metrics capture."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx
from contextlib import asynccontextmanager

try:
    from asgi_lifespan import LifespanManager
except ImportError:
    @asynccontextmanager
    async def LifespanManager(app_obj):
        async with app_obj.router.lifespan_context(app_obj):
            yield

from config import config
from event_queue import event_queue
from main import app
from storage import get_audit_log, list_incidents, reset_runtime_state

API_KEY = (os.getenv("API_KEY") or config.api.api_key or "dev-secret-key").strip()
API_HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}
DEMO_DIR = Path(__file__).resolve().parent
RESULTS_DIR = DEMO_DIR / "results"


def load_scenarios() -> List[Dict[str, Any]]:
    scenarios = []
    for path in sorted(DEMO_DIR.glob("scenario_*.json")):
        with path.open("r", encoding="utf-8") as handle:
            scenario = json.load(handle)
        scenario["_path"] = str(path)
        scenarios.append(scenario)
    return scenarios


async def wait_for_queue():
    while event_queue.metrics.depth > 0:
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.1)  # small buffer for final incident correlation

async def _run_step(client: httpx.AsyncClient, step: Dict[str, Any]) -> Dict[str, Any]:
    kind = step["kind"]
    if kind == "telemetry":
        resp = await client.post("/telemetry", json=step["body"], headers=API_HEADERS)
        await wait_for_queue()
        return resp.json()
    if kind == "honeypot":
        resp = await client.post("/honeypot", json=step["body"], headers=API_HEADERS)
        await wait_for_queue()
        return resp.json()
    if kind == "action":
        incident_id = step["incident_id"]
        if incident_id == "latest":
            incidents = list_incidents()
            if not incidents:
                return {"skipped": True, "reason": "no incidents available"}
            incident_id = incidents[-1]["id"]
        resp = await client.post(
            f"/incidents/{incident_id}/action",
            json=step["body"],
            headers=API_HEADERS,
        )
        return resp.json()
    raise ValueError(f"unsupported step kind: {kind}")


async def run_scenario(client: httpx.AsyncClient, scenario: Dict[str, Any]) -> Dict[str, Any]:
    reset_runtime_state()
    scenario_start = time.time()
    first_detection_at = None
    action_completed_at = None
    responses: List[Dict[str, Any]] = []

    for step in scenario.get("steps", []):
        response = await _run_step(client, step)
        responses.append({"kind": step["kind"], "response": response})
        incidents = list_incidents()
        if first_detection_at is None and incidents:
            first_detection_at = time.time()
        if step["kind"] == "action" and not response.get("skipped"):
            action_completed_at = time.time()

    incidents = list_incidents()
    incident_count = len(incidents)
    audit_count = sum(len(get_audit_log(incident["id"])) for incident in incidents)
    expected = scenario.get("expected", {})
    min_incidents = int(expected.get("min_incidents", 0))
    should_detect = bool(expected.get("should_detect", min_incidents > 0))
    detected = incident_count >= min_incidents if should_detect else incident_count > 0

    result = {
        "scenario_id": scenario["scenario_id"],
        "name": scenario["name"],
        "expected_positive": should_detect,
        "incident_count": incident_count,
        "audit_count": audit_count,
        "detected": detected if should_detect else incident_count > 0,
        "false_positive": (not should_detect) and incident_count > 0,
        "mttd_seconds": round(first_detection_at - scenario_start, 4) if first_detection_at else None,
        "mttr_seconds": round(action_completed_at - first_detection_at, 4)
        if first_detection_at and action_completed_at
        else None,
        "responses": responses,
    }
    return result


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    positive = [r for r in results if r["expected_positive"]]
    negative = [r for r in results if not r["expected_positive"]]
    detected_positive = [r for r in positive if r["incident_count"] > 0]
    false_positives = [r for r in negative if r["false_positive"]]
    mttd_values = [r["mttd_seconds"] for r in detected_positive if r["mttd_seconds"] is not None]
    mttr_values = [r["mttr_seconds"] for r in results if r["mttr_seconds"] is not None]

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario_count": len(results),
        "detection_rate": round(len(detected_positive) / len(positive), 4) if positive else 0.0,
        "fp_rate": round(len(false_positives) / len(negative), 4) if negative else 0.0,
        "mttd_seconds": round(sum(mttd_values) / len(mttd_values), 4) if mttd_values else None,
        "mttr_seconds": round(sum(mttr_values) / len(mttr_values), 4) if mttr_values else None,
        "results": results,
    }


def write_metrics(summary: Dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / "latest_metrics.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    return output_path


async def run_all_scenarios() -> Dict[str, Any]:
    scenarios = load_scenarios()
    
    # We must use LifespanManager to ensure the FastAPI lifespan (which starts the queue) runs
    async with LifespanManager(app):
        # We need to hit the app directly. httpx can do this with ASGITransport in recent versions,
        # or we use the old 'app' parameter. 
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            results = []
            for scenario in scenarios:
                res = await run_scenario(client, scenario)
                results.append(res)
                
    summary = summarize_results(results)
    output_path = write_metrics(summary)
    summary["output_path"] = str(output_path)
    return summary


if __name__ == "__main__":
    metrics = asyncio.run(run_all_scenarios())
    print(json.dumps(metrics, indent=2))
