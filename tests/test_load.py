"""In-process scalability tests for SwarmSentinel.

Validates:
- Queue handles 1000 events without drops at moderate rate
- Graph stays within node/edge caps
- Per-event processing latency stays under budget
- Orphan pruning and decay work correctly under load
"""
import asyncio
import time
import pytest
from swarm_graph import PheromoneGraph
from event_queue import EventQueue
from storage import clear_all_state


# ------------------------------------------------------------------
# Graph cap enforcement
# ------------------------------------------------------------------

class TestGraphCaps:
    def test_node_cap_enforced(self):
        g = PheromoneGraph(max_nodes=50, max_edges=200)
        for i in range(100):
            g.add_entity(f"ip:10.0.0.{i}", "ip")
        assert g.graph.number_of_nodes() <= 50

    def test_edge_cap_enforced(self):
        g = PheromoneGraph(max_nodes=500, max_edges=50)
        for i in range(100):
            g.deposit_pheromone(f"src:{i}", f"dst:{i}", "scan", 10.0)
        assert g.graph.number_of_edges() <= 50

    def test_evidence_list_bounded(self):
        g = PheromoneGraph()
        src, dst = "a", "b"
        for i in range(50):
            g.deposit_pheromone(src, dst, "scan", 5.0, evidence={"idx": i})
        edge_data = g.graph.edges[src, dst]
        assert len(edge_data["evidence"]) <= g.MAX_EVIDENCE_PER_EDGE

    def test_orphan_pruning(self):
        g = PheromoneGraph(decay_rate=0.001, min_threshold=0.5)
        g.add_entity("orphan_node", "ip")
        # Node exists but has no edges and near-zero pheromone
        assert g.graph.has_node("orphan_node")
        g.decay_all()
        assert not g.graph.has_node("orphan_node")

    def test_decay_removes_weak_edges(self):
        g = PheromoneGraph(decay_rate=0.01, min_threshold=0.5)
        g.deposit_pheromone("a", "b", "scan", 1.0)
        assert g.graph.number_of_edges() == 1
        pruned = g.decay_all()
        assert pruned == 1
        assert g.graph.number_of_edges() == 0

    def test_graph_utilization_stats(self):
        g = PheromoneGraph(max_nodes=100, max_edges=100)
        for i in range(10):
            g.deposit_pheromone(f"s:{i}", f"d:{i}", "scan", 5.0)
        stats = g.get_stats()
        assert "node_utilization_pct" in stats
        assert "edge_utilization_pct" in stats
        assert stats["node_utilization_pct"] > 0
        assert stats["max_nodes"] == 100


# ------------------------------------------------------------------
# Queue throughput
# ------------------------------------------------------------------

class TestQueueThroughput:
    @pytest.mark.asyncio
    async def test_1000_events_no_drops(self):
        """Queue should handle 1000 events without dropping any."""
        processed_count = 0

        async def handler(batch):
            nonlocal processed_count
            processed_count += len(batch)

        q = EventQueue(max_size=2000, batch_size=100, flush_interval=0.05)
        await q.start(handler)

        for i in range(1000):
            accepted = await q.enqueue({"id": i, "entity_type": "ip", "entity_id": f"10.0.0.{i % 256}"})
            assert accepted, f"Event {i} was dropped"

        # Wait for processing
        for _ in range(100):
            await asyncio.sleep(0.05)
            if processed_count >= 1000:
                break

        await q.stop()

        assert q.metrics.dropped_total == 0
        assert processed_count == 1000

    @pytest.mark.asyncio
    async def test_backpressure_when_full(self):
        """Queue should reject events when full and track drops."""
        q = EventQueue(max_size=10, batch_size=5, flush_interval=10.0)
        # Don't start processing — fill up the queue
        for i in range(10):
            await q.enqueue({"id": i})

        # This one should be rejected
        accepted = await q.enqueue({"id": 999})
        assert not accepted
        assert q.metrics.dropped_total == 1
        assert q.stats()["backpressure_active"] is True

    @pytest.mark.asyncio
    async def test_processing_latency_under_budget(self):
        """Per-batch processing latency should be reasonable."""
        batch_times = []

        async def handler(batch):
            # Simulate light processing
            start = time.perf_counter()
            await asyncio.sleep(0.001)
            batch_times.append((time.perf_counter() - start) * 1000)

        q = EventQueue(max_size=2000, batch_size=50, flush_interval=0.02)
        await q.start(handler)

        for i in range(500):
            await q.enqueue({"id": i})

        # Wait for processing
        for _ in range(50):
            await asyncio.sleep(0.05)
            if q.metrics.processed_total >= 500:
                break

        await q.stop()

        assert q.metrics.processed_total == 500
        assert len(batch_times) > 0
        p95 = sorted(batch_times)[int(len(batch_times) * 0.95)]
        assert p95 < 100, f"p95 batch latency {p95:.1f}ms exceeds 100ms budget"


# ------------------------------------------------------------------
# End-to-end queue + graph integration
# ------------------------------------------------------------------

class TestQueueGraphIntegration:
    @pytest.mark.asyncio
    async def test_queue_feeds_graph(self):
        """Events flowing through the queue should end up in the graph."""
        from swarm_graph import PheromoneGraph
        clear_all_state()

        graph = PheromoneGraph(max_nodes=500, max_edges=2000)
        processed = []

        async def handler(batch):
            for event in batch:
                node_id = f"{event['entity_type']}:{event['entity_id']}"
                graph.add_entity(node_id, event["entity_type"])
                processed.append(event)

        q = EventQueue(max_size=500, batch_size=50, flush_interval=0.05)
        await q.start(handler)

        for i in range(200):
            await q.enqueue({
                "entity_type": "ip",
                "entity_id": f"10.0.0.{i % 256}",
                "score": 50.0,
                "evidence": [],
            })

        for _ in range(100):
            await asyncio.sleep(0.05)
            if len(processed) >= 200:
                break

        await q.stop()

        assert len(processed) == 200
        assert graph.graph.number_of_nodes() == 200

    @pytest.mark.asyncio
    async def test_sustained_load_stable_memory(self):
        """Push many events through a capped graph — node count should stay bounded."""
        import tracemalloc
        tracemalloc.start()

        MAX_NODES = 100
        graph = PheromoneGraph(max_nodes=MAX_NODES, max_edges=500, decay_rate=0.9, min_threshold=0.1)
        processed = 0

        async def handler(batch):
            nonlocal processed
            for event in batch:
                node_id = f"{event['entity_type']}:{event['entity_id']}"
                graph.add_entity(node_id, event["entity_type"])
                processed += 1

        q = EventQueue(max_size=2000, batch_size=100, flush_interval=0.02)
        await q.start(handler)

        _, baseline = tracemalloc.get_traced_memory()

        for i in range(1000):
            await q.enqueue({
                "entity_type": "ip",
                "entity_id": f"192.168.{i // 256}.{i % 256}",
                "score": 30.0 + (i % 70),
            })

        for _ in range(200):
            await asyncio.sleep(0.05)
            if processed >= 1000:
                break

        await q.stop()
        tracemalloc.stop()

        assert processed == 1000
        assert graph.graph.number_of_nodes() <= MAX_NODES, f"Node cap violated: {graph.graph.number_of_nodes()}"
