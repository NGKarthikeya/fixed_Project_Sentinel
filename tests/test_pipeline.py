"""
Pipeline Integration Tests
============================

End-to-end tests for the event processing pipeline:
telemetry → pheromone → correlation → incident
"""

import pytest
import time


class TestIngestionEngine:
    """Tests for the log ingestion engine."""

    def test_ingest_native_json(self):
        from ingestion import IngestionEngine
        engine = IngestionEngine()
        event = engine.ingest_json({
            "entity_type": "ip",
            "entity_id": "10.0.0.1",
            "score": 75,
            "evidence": [{"type": "test", "text": "test event"}],
        })
        assert event is not None
        assert event["entity_type"] == "ip"
        assert event["entity_id"] == "10.0.0.1"
        assert event["score"] == 75.0

    def test_ingest_generic_json(self):
        from ingestion import IngestionEngine
        engine = IngestionEngine()
        event = engine.ingest_json({
            "src_ip": "192.168.1.100",
            "severity": 80,
            "message": "Suspicious login attempt",
        })
        assert event is not None
        assert event["entity_id"] == "192.168.1.100"
        assert event["score"] == 80.0

    def test_ingest_syslog(self):
        from ingestion import IngestionEngine
        engine = IngestionEngine()
        raw = "<34>1 2026-06-30T12:00:00Z firewall-01 sshd 12345 - - Failed password for root from 10.20.30.40 port 22"
        event = engine.ingest_syslog(raw)
        assert event is not None
        assert event["entity_id"] == "10.20.30.40"
        assert event["entity_type"] == "ip"

    def test_ingest_csv(self):
        from ingestion import IngestionEngine
        engine = IngestionEngine()
        csv_data = "src_ip,severity,message\n10.0.0.1,80,Port scan detected\n10.0.0.2,30,Normal login"
        events = engine.ingest_csv(csv_data)
        assert len(events) == 2
        assert events[0]["entity_id"] == "10.0.0.1"
        assert events[0]["score"] == 80.0

    def test_ingest_cef(self):
        from ingestion import IngestionEngine
        engine = IngestionEngine()
        raw = "CEF:0|SecurityVendor|Product|1.0|100|Intrusion Detected|8|src=10.0.0.5 dst=10.0.0.1"
        event = engine.ingest_cef(raw)
        assert event is not None
        assert event["entity_id"] == "10.0.0.5"
        assert event["score"] == 85  # severity 8

    def test_ingestion_stats(self):
        from ingestion import IngestionEngine
        engine = IngestionEngine()
        engine.ingest_json({"entity_type": "ip", "entity_id": "1.2.3.4", "score": 10})
        engine.ingest_json({"entity_type": "ip", "entity_id": "5.6.7.8", "score": 20})
        stats = engine.stats()
        assert stats["ingested_total"] == 2


class TestContainmentEngine:
    """Tests for the containment engine."""

    def test_block_ip(self):
        from containment import ContainmentEngine
        engine = ContainmentEngine()
        result = engine.execute_action("block_ip", "10.0.0.1", "ip", actor="test", reason="port scan")
        assert result["status"] == "ok"
        assert engine.is_blocked("10.0.0.1")

    def test_block_with_ttl(self):
        from containment import ContainmentEngine
        engine = ContainmentEngine()
        engine.execute_action("block_ip", "10.0.0.1", "ip", ttl_seconds=0, actor="test")
        # TTL of 0 means already expired
        import time
        time.sleep(0.01)
        assert not engine.is_blocked("10.0.0.1")

    def test_isolate_host(self):
        from containment import ContainmentEngine
        engine = ContainmentEngine()
        result = engine.execute_action("isolate_host", "srv-dc-01", "host", actor="analyst")
        assert result["status"] == "ok"

    def test_release(self):
        from containment import ContainmentEngine
        engine = ContainmentEngine()
        engine.execute_action("block_ip", "10.0.0.1", "ip", actor="test")
        assert engine.is_blocked("10.0.0.1")
        engine.execute_action("release", "10.0.0.1", "ip", actor="test")
        assert not engine.is_blocked("10.0.0.1")

    def test_audit_trail(self):
        from containment import ContainmentEngine
        engine = ContainmentEngine()
        engine.execute_action("block_ip", "10.0.0.1", "ip", actor="alice", reason="scan")
        engine.execute_action("escalate", "10.0.0.1", "ip", actor="bob", incident_id=1)
        trail = engine.get_audit_trail(entity_id="10.0.0.1")
        assert len(trail) == 2

    def test_unknown_action(self):
        from containment import ContainmentEngine
        engine = ContainmentEngine()
        result = engine.execute_action("self_destruct", "10.0.0.1", "ip")
        assert result["status"] == "error"


class TestEventQueue:
    """Tests for the async event queue."""

    @pytest.mark.asyncio
    async def test_enqueue_dequeue(self):
        from event_queue import EventQueue
        q = EventQueue(max_size=10, batch_size=5)
        assert await q.enqueue({"test": 1})
        assert q.stats()["current_depth"] == 1

    @pytest.mark.asyncio
    async def test_backpressure(self):
        from event_queue import EventQueue
        q = EventQueue(max_size=2, batch_size=1)
        await q.enqueue({"a": 1})
        await q.enqueue({"b": 2})
        result = await q.enqueue({"c": 3})  # should fail
        assert result is False
        assert q.metrics.dropped_total == 1


class TestConfig:
    """Tests for centralized configuration."""

    def test_config_loads(self):
        from config import AppConfig
        cfg = AppConfig.from_env()
        assert cfg.version == "2.0.0"
        assert cfg.graph.decay_rate == 0.95

    def test_config_rejects_placeholder_api_key(self, monkeypatch):
        from config import AppConfig, ConfigError
        monkeypatch.setenv("API_KEY", "YOUR_API_KEY_HERE")
        with pytest.raises(ConfigError):
            AppConfig.from_env().validate_runtime_requirements()

    def test_config_to_dict_redacts_secrets(self):
        from config import AppConfig
        cfg = AppConfig.from_env()
        d = cfg.to_dict()
        assert "api_key" not in d  # should not leak in the keys
        assert d["api_key_set"] is not None


class TestGraphBackend:
    """Tests for the graph backend abstraction."""

    def test_inmemory_backend_basic(self):
        from graph_backend import InMemoryBackend
        backend = InMemoryBackend()
        backend.add_node("A", {"type": "ip"})
        assert backend.has_node("A")
        assert backend.node_count() == 1

    def test_inmemory_backend_edges(self):
        from graph_backend import InMemoryBackend
        backend = InMemoryBackend()
        backend.add_node("A", {})
        backend.add_node("B", {})
        backend.add_edge("A", "B", {"weight": 5.0})
        assert backend.has_edge("A", "B")
        assert backend.edge_count() == 1

    def test_inmemory_backend_pagerank(self):
        from graph_backend import InMemoryBackend
        backend = InMemoryBackend()
        backend.add_node("A", {})
        backend.add_node("B", {})
        backend.add_edge("A", "B", {"weight": 1.0})
        pr = backend.pagerank()
        assert len(pr) == 2

    def test_redis_backend_fallback(self):
        from graph_backend import RedisGraphBackend
        backend = RedisGraphBackend(redis_url=None)  # no redis = fallback
        backend.add_node("X", {"type": "test"})
        assert backend.has_node("X")


class TestFullPipeline:
    """End-to-end pipeline test."""

    def test_event_to_incident(self):
        """Test: event → pheromone → correlation → incident."""
        from swarm_graph import PheromoneGraph
        from swarm import publish_pheromone

        # Reset state
        from swarm_graph import pheromone_graph
        pheromone_graph.clear()

        events = [
            {"entity_type": "ip", "entity_id": "attacker-1", "score": 85,
             "evidence": [{"type": "scan", "text": "port scan", "source": "fw"}], "ts": time.time()},
            {"entity_type": "ip", "entity_id": "attacker-1", "score": 90,
             "evidence": [{"type": "brute", "text": "brute force", "source": "ids"}], "ts": time.time()},
        ]

        for ev in events:
            result = publish_pheromone(ev)
            assert "published" in result

        stats = pheromone_graph.get_stats()
        assert stats["node_count"] > 0
