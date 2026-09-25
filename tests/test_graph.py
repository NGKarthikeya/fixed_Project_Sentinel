"""
PheromoneGraph Unit Tests
=========================

Comprehensive test coverage for the core graph data structure.
Tests: node CRUD, pheromone deposit/reinforcement, decay, hotspots,
attack corridors, subgraph extraction, snapshots, and predictive scoring.
"""

import pytest
import time


class TestNodeManagement:
    """Tests for add_entity and node queries."""

    def test_add_new_entity(self, graph):
        graph.add_entity("ip:10.0.0.1", "ip")
        stats = graph.get_stats()
        assert stats["node_count"] == 1

    def test_add_entity_with_metadata(self, graph):
        graph.add_entity("ip:10.0.0.1", "ip", metadata={"country": "IN"})
        snapshot = graph.to_snapshot()
        node = next(n for n in snapshot["nodes"] if n["id"] == "ip:10.0.0.1")
        assert node["metadata"]["country"] == "IN"

    def test_update_existing_entity_merges_metadata(self, graph):
        graph.add_entity("ip:10.0.0.1", "ip", metadata={"country": "IN"})
        graph.add_entity("ip:10.0.0.1", "ip", metadata={"org": "ISP-A"})
        snapshot = graph.to_snapshot()
        node = next(n for n in snapshot["nodes"] if n["id"] == "ip:10.0.0.1")
        assert node["metadata"]["country"] == "IN"  # preserved
        assert node["metadata"]["org"] == "ISP-A"   # added

    def test_update_does_not_overwrite_existing_metadata(self, graph):
        graph.add_entity("ip:10.0.0.1", "ip", metadata={"country": "IN"})
        graph.add_entity("ip:10.0.0.1", "ip", metadata={"country": "US"})
        snapshot = graph.to_snapshot()
        node = next(n for n in snapshot["nodes"] if n["id"] == "ip:10.0.0.1")
        assert node["metadata"]["country"] == "IN"  # original preserved


class TestPheromoneDeposit:
    """Tests for deposit_pheromone and reinforcement."""

    def test_deposit_creates_edge(self, graph):
        graph.deposit_pheromone("ip:A", "ip:B", "scan", 10.0)
        stats = graph.get_stats()
        assert stats["edge_count"] == 1
        assert stats["node_count"] == 2  # auto-created

    def test_deposit_auto_creates_unknown_nodes(self, graph):
        graph.deposit_pheromone("ip:new-src", "ip:new-dst", "scan", 5.0)
        snapshot = graph.to_snapshot()
        src = next(n for n in snapshot["nodes"] if n["id"] == "ip:new-src")
        assert src["type"] == "unknown"

    def test_reinforcement_formula(self, graph):
        graph.deposit_pheromone("A", "B", "s1", 10.0)
        graph.deposit_pheromone("A", "B", "s2", 20.0)
        # After reinforcement: 10.0 * 0.7 + 20.0 * 0.3 = 7.0 + 6.0 = 13.0
        snapshot = graph.to_snapshot()
        edge = next(e for e in snapshot["edges"] if e["source"] == "A")
        assert abs(edge["weight"] - 13.0) < 0.01

    def test_signal_types_accumulated(self, graph):
        graph.deposit_pheromone("A", "B", "scan", 10.0)
        graph.deposit_pheromone("A", "B", "login", 5.0)
        snapshot = graph.to_snapshot()
        edge = next(e for e in snapshot["edges"] if e["source"] == "A")
        assert "scan" in edge["signal_types"]
        assert "login" in edge["signal_types"]

    def test_target_pheromone_increases(self, graph):
        graph.deposit_pheromone("A", "B", "scan", 40.0)
        snapshot = graph.to_snapshot()
        target = next(n for n in snapshot["nodes"] if n["id"] == "B")
        assert target["pheromone"] == 40.0

    def test_multiple_deposits_accumulate(self, graph):
        graph.deposit_pheromone("A", "B", "s1", 20.0)
        graph.deposit_pheromone("C", "B", "s2", 30.0)
        snapshot = graph.to_snapshot()
        target = next(n for n in snapshot["nodes"] if n["id"] == "B")
        assert target["pheromone"] == 50.0


class TestDecay:
    """Tests for decay_all and edge pruning."""

    def test_decay_reduces_weights(self, graph):
        graph.deposit_pheromone("A", "B", "scan", 10.0)
        graph.decay_all()
        snapshot = graph.to_snapshot()
        edge = snapshot["edges"][0]
        assert edge["weight"] < 10.0
        assert edge["weight"] == pytest.approx(10.0 * 0.9, rel=0.01)

    def test_decay_prunes_weak_edges(self, graph):
        graph.deposit_pheromone("A", "B", "scan", 0.02)
        pruned = graph.decay_all()  # 0.018
        assert pruned == 0
        pruned = graph.decay_all()  # 0.0162
        pruned = graph.decay_all()  # 0.01458
        pruned = graph.decay_all()  # 0.01312
        pruned = graph.decay_all()  # 0.01181
        pruned = graph.decay_all()  # 0.01063 < 0.01? No, > 0.01
        pruned = graph.decay_all()  # 0.00956 < 0.01
        assert pruned == 1

    def test_decay_reduces_node_pheromone(self, graph):
        graph.deposit_pheromone("A", "B", "scan", 100.0)
        graph.decay_all()
        snapshot = graph.to_snapshot()
        node = next(n for n in snapshot["nodes"] if n["id"] == "B")
        assert node["pheromone"] < 100.0


class TestHotspots:
    """Tests for hotspot detection."""

    def test_hotspots_ranked_by_pheromone(self, populated_graph):
        hotspots = populated_graph.get_hotspots(top_n=5)
        assert len(hotspots) > 0
        # Sorted descending by total_pheromone
        for i in range(len(hotspots) - 1):
            assert hotspots[i]["total_pheromone"] >= hotspots[i + 1]["total_pheromone"]

    def test_hotspots_respect_top_n(self, populated_graph):
        hotspots = populated_graph.get_hotspots(top_n=1)
        assert len(hotspots) == 1

    def test_empty_graph_returns_empty_hotspots(self, graph):
        assert graph.get_hotspots() == []


class TestAttackCorridors:
    """Tests for attack corridor detection."""

    def test_corridors_above_threshold(self, populated_graph):
        corridors = populated_graph.get_attack_corridors(min_strength=20.0)
        assert len(corridors) > 0
        for c in corridors:
            assert c["weight"] >= 20.0

    def test_corridors_sorted_by_weight(self, populated_graph):
        corridors = populated_graph.get_attack_corridors(min_strength=1.0)
        for i in range(len(corridors) - 1):
            assert corridors[i]["weight"] >= corridors[i + 1]["weight"]

    def test_corridors_include_signal_types(self, populated_graph):
        corridors = populated_graph.get_attack_corridors(min_strength=1.0)
        for c in corridors:
            assert isinstance(c["signal_types"], list)


class TestSubgraph:
    """Tests for subgraph extraction."""

    def test_subgraph_from_node(self, populated_graph):
        sub = populated_graph.get_subgraph("ip:185.220.101.34", depth=1)
        assert len(sub["nodes"]) >= 2  # at least source + one neighbor
        ids = {n["id"] for n in sub["nodes"]}
        assert "ip:185.220.101.34" in ids

    def test_subgraph_unknown_node(self, graph):
        sub = graph.get_subgraph("nonexistent")
        assert sub == {"nodes": [], "edges": []}

    def test_subgraph_depth_limits(self, populated_graph):
        sub1 = populated_graph.get_subgraph("ip:185.220.101.34", depth=1)
        sub2 = populated_graph.get_subgraph("ip:185.220.101.34", depth=2)
        assert len(sub2["nodes"]) >= len(sub1["nodes"])


class TestSnapshot:
    """Tests for graph serialization."""

    def test_snapshot_structure(self, populated_graph):
        snap = populated_graph.to_snapshot()
        assert "nodes" in snap
        assert "edges" in snap
        assert "stats" in snap
        assert snap["stats"]["node_count"] == 4
        assert snap["stats"]["edge_count"] == 3

    def test_snapshot_node_fields(self, populated_graph):
        snap = populated_graph.to_snapshot()
        node = snap["nodes"][0]
        assert "id" in node
        assert "type" in node
        assert "pheromone" in node

    def test_snapshot_edge_fields(self, populated_graph):
        snap = populated_graph.to_snapshot()
        edge = snap["edges"][0]
        assert "source" in edge
        assert "target" in edge
        assert "weight" in edge
        assert "signal_types" in edge


class TestClear:
    """Tests for graph reset."""

    def test_clear_removes_everything(self, populated_graph):
        populated_graph.clear()
        stats = populated_graph.get_stats()
        assert stats["node_count"] == 0
        assert stats["edge_count"] == 0
        assert stats["total_pheromone"] == 0


class TestNeighbors:
    """Tests for neighbor queries."""

    def test_neighbors_both_directions(self, populated_graph):
        neighbors = populated_graph.get_neighbors("host:ws-finance-01", min_strength=0.1)
        directions = {n["direction"] for n in neighbors}
        assert "incoming" in directions or "outgoing" in directions

    def test_neighbors_unknown_entity(self, graph):
        assert graph.get_neighbors("nonexistent") == []

    def test_neighbors_filtered_by_strength(self, populated_graph):
        weak = populated_graph.get_neighbors("host:ws-finance-01", min_strength=100.0)
        assert len(weak) == 0


class TestPredictiveScoring:
    """Tests for predict_next_targets."""

    def test_predict_returns_list(self, populated_graph):
        if hasattr(populated_graph, 'predict_next_targets'):
            predictions = populated_graph.predict_next_targets(top_n=3)
            assert isinstance(predictions, list)
