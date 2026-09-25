"""Shared pytest fixtures for SwarmSentinel tests."""

import os

os.environ.setdefault("API_KEY", "test-api-key")
os.environ.setdefault("ENVIRONMENT", "test")

import pytest
from swarm_graph import PheromoneGraph


@pytest.fixture
def graph():
    """Fresh PheromoneGraph instance for each test."""
    g = PheromoneGraph(decay_rate=0.9, min_threshold=0.01)
    yield g
    g.clear()


@pytest.fixture
def populated_graph(graph):
    """Graph pre-populated with a small attack scenario."""
    graph.add_entity("ip:185.220.101.34", "ip")
    graph.add_entity("host:ws-finance-01", "host")
    graph.add_entity("user:admin@corp.local", "user")
    graph.add_entity("domain:evil.com", "domain")

    graph.deposit_pheromone("ip:185.220.101.34", "host:ws-finance-01", "port_scan", 40.0)
    graph.deposit_pheromone("ip:185.220.101.34", "user:admin@corp.local", "credential_access", 60.0)
    graph.deposit_pheromone("host:ws-finance-01", "domain:evil.com", "dns_query", 25.0)
    return graph
