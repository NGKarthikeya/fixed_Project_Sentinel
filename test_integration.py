"""Quick integration test for the full SwarmSentinel pipeline."""
import os
import time
import pytest
from fastapi.testclient import TestClient
from main import app
from config import config

os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = "true"
API_KEY = (os.getenv("API_KEY") or config.api.api_key or "dev-secret-key").strip()
H = {"x-api-key": API_KEY, "Content-Type": "application/json"}
H_GET = {"x-api-key": API_KEY}


def run_pipeline_test():
    client = TestClient(app)

    # Run APT killchain scenario
    r = client.post("/swarm/simulate", headers=H, json={
        "action": "scenario",
        "scenario": "apt_killchain",
        "events_per_second": 5.0,
    })
    assert r.status_code == 200, f"Simulation failed: {r.text}"
    print("Simulation:", r.json())

    time.sleep(1)

    # Check graph
    r = client.get("/swarm/graph", headers=H_GET)
    assert r.status_code == 200, f"Graph failed: {r.text}"
    stats = r.json()["stats"]
    print(f"Graph: {stats['node_count']} nodes, {stats['edge_count']} edges, pheromone={stats['total_pheromone']:.1f}")

    # Check hotspots
    r = client.get("/swarm/hotspots?top_n=5", headers=H_GET)
    assert r.status_code == 200, f"Hotspots failed: {r.text}"
    hotspots = r.json()["hotspots"]
    print(f"Hotspots: {len(hotspots)}")

    # Check incidents
    r = client.get("/incidents", headers=H_GET)
    assert r.status_code == 200, f"Incidents failed: {r.text}"
    incidents = r.json()["incidents"]
    print(f"Incidents: {len(incidents)}")

    # Check corridors
    r = client.get("/swarm/corridors?min_strength=0.5", headers=H_GET)
    assert r.status_code == 200, f"Corridors failed: {r.text}"
    corridors = r.json()["corridors"]
    print(f"Attack corridors: {len(corridors)}")

    print("\n=== Full pipeline test PASSED ===")


def test_full_pipeline_integration():
    """Integration test suite runner."""
    run_pipeline_test()


if __name__ == "__main__":
    run_pipeline_test()
