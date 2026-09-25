#!/usr/bin/env python
"""
SwarmSentinel Load Test — Benchmark Script
============================================

Usage:
    python scripts/load_test.py --target http://localhost:8000 --rate 50 --duration 60
    python scripts/load_test.py --in-process --events 1000 --rate 100

Produces a JSON benchmark report with p50/p95/p99 latency, throughput,
drop rate, and graph growth metrics.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class BenchmarkResult:
    """Structured benchmark report."""
    mode: str = "in-process"
    total_events: int = 0
    accepted_events: int = 0
    dropped_events: int = 0
    error_events: int = 0
    duration_seconds: float = 0.0
    throughput_eps: float = 0.0
    drop_rate_pct: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_min_ms: float = 0.0
    latency_max_ms: float = 0.0
    graph_nodes_start: int = 0
    graph_nodes_end: int = 0
    graph_edges_start: int = 0
    graph_edges_end: int = 0
    queue_max_depth: int = 0
    memory_start_mb: float = 0.0
    memory_end_mb: float = 0.0
    samples: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "samples"}

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  SwarmSentinel Load Test Report",
            "=" * 60,
            f"  Mode:            {self.mode}",
            f"  Total Events:    {self.total_events}",
            f"  Accepted:        {self.accepted_events}",
            f"  Dropped:         {self.dropped_events} ({self.drop_rate_pct:.1f}%)",
            f"  Errors:          {self.error_events}",
            f"  Duration:        {self.duration_seconds:.1f}s",
            f"  Throughput:      {self.throughput_eps:.1f} events/sec",
            "-" * 60,
            f"  Latency p50:     {self.latency_p50_ms:.2f}ms",
            f"  Latency p95:     {self.latency_p95_ms:.2f}ms",
            f"  Latency p99:     {self.latency_p99_ms:.2f}ms",
            f"  Latency min:     {self.latency_min_ms:.2f}ms",
            f"  Latency max:     {self.latency_max_ms:.2f}ms",
            "-" * 60,
            f"  Graph nodes:     {self.graph_nodes_start} -> {self.graph_nodes_end}",
            f"  Graph edges:     {self.graph_edges_start} -> {self.graph_edges_end}",
            f"  Queue max depth: {self.queue_max_depth}",
            f"  Memory:          {self.memory_start_mb:.1f}MB -> {self.memory_end_mb:.1f}MB",
            "=" * 60,
        ]
        return "\n".join(lines)


def _percentile(data: List[float], pct: float) -> float:
    if not data:
        return 0.0
    k = (len(data) - 1) * (pct / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(data):
        return data[-1]
    return data[f] + (data[c] - data[f]) * (k - f)


async def run_in_process(events: int, rate: float, max_nodes: int = 500, max_edges: int = 2000) -> BenchmarkResult:
    """Run load test in-process without HTTP overhead."""
    import tracemalloc
    from event_queue import EventQueue
    from swarm_graph import PheromoneGraph
    from telemetry_simulator import TelemetrySimulator

    tracemalloc.start()

    graph = PheromoneGraph(max_nodes=max_nodes, max_edges=max_edges)
    result = BenchmarkResult(mode="in-process", total_events=events)
    latencies: List[float] = []
    max_depth = 0

    result.graph_nodes_start = graph.graph.number_of_nodes()
    result.graph_edges_start = graph.graph.number_of_edges()
    _, result.memory_start_mb = tracemalloc.get_traced_memory()
    result.memory_start_mb /= 1024 * 1024

    processed = 0

    async def handler(batch):
        nonlocal processed
        for event in batch:
            node_id = f"{event['entity_type']}:{event['entity_id']}"
            graph.add_entity(node_id, event["entity_type"])
            if event.get("evidence"):
                for ev in event["evidence"]:
                    ref_id = ev.get("source", f"ref:{processed}")
                    graph.deposit_pheromone(node_id, ref_id, ev.get("type", "scan"), event.get("score", 10) * 0.4, evidence=ev)
            processed += 1
        if processed % 200 == 0:
            graph.decay_all()

    q = EventQueue(max_size=events + 100, batch_size=100, flush_interval=0.02)
    await q.start(handler)

    # Generate events
    sim = TelemetrySimulator()
    all_events = sim.generate_normal_traffic(num_events=events)

    delay = 1.0 / rate if rate > 0 else 0
    start_time = time.perf_counter()

    for event in all_events:
        t0 = time.perf_counter()
        accepted = await q.enqueue(event)
        latencies.append((time.perf_counter() - t0) * 1000)

        if accepted:
            result.accepted_events += 1
        else:
            result.dropped_events += 1

        current_depth = q._queue.qsize()
        if current_depth > max_depth:
            max_depth = current_depth

        if delay > 0:
            await asyncio.sleep(delay)

    # Wait for drain
    for _ in range(500):
        await asyncio.sleep(0.02)
        if processed >= result.accepted_events:
            break

    await q.stop()

    end_time = time.perf_counter()
    result.duration_seconds = end_time - start_time
    result.throughput_eps = result.accepted_events / result.duration_seconds if result.duration_seconds > 0 else 0

    result.drop_rate_pct = (result.dropped_events / result.total_events * 100) if result.total_events > 0 else 0
    result.queue_max_depth = max_depth

    latencies.sort()
    result.latency_p50_ms = _percentile(latencies, 50)
    result.latency_p95_ms = _percentile(latencies, 95)
    result.latency_p99_ms = _percentile(latencies, 99)
    result.latency_min_ms = latencies[0] if latencies else 0
    result.latency_max_ms = latencies[-1] if latencies else 0

    result.graph_nodes_end = graph.graph.number_of_nodes()
    result.graph_edges_end = graph.graph.number_of_edges()

    _, peak = tracemalloc.get_traced_memory()
    result.memory_end_mb = peak / 1024 / 1024
    tracemalloc.stop()

    return result


async def run_http(target: str, rate: float, duration: int, api_key: str) -> BenchmarkResult:
    """Run load test against a live HTTP server."""
    try:
        import httpx
    except ImportError:
        print("ERROR: httpx is required for HTTP load tests. Run: pip install httpx")
        sys.exit(1)

    from telemetry_simulator import TelemetrySimulator

    result = BenchmarkResult(mode="http", total_events=0)
    latencies: List[float] = []

    sim = TelemetrySimulator()
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    # Get initial metrics
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{target}/metrics", headers=headers)
            if resp.status_code == 200:
                metrics = resp.json()
                result.graph_nodes_start = metrics.get("graph", {}).get("node_count", 0)
                result.graph_edges_start = metrics.get("graph", {}).get("edge_count", 0)
        except Exception:
            pass

    delay = 1.0 / rate if rate > 0 else 0
    end_at = time.time() + duration

    async with httpx.AsyncClient(timeout=30) as client:
        while time.time() < end_at:
            events = sim.generate_normal_traffic(num_events=1)
            event = events[0]

            t0 = time.perf_counter()
            try:
                resp = await client.post(
                    f"{target}/telemetry",
                    json=event,
                    headers=headers,
                )
                lat = (time.perf_counter() - t0) * 1000
                latencies.append(lat)
                result.total_events += 1

                if resp.status_code in (200, 202):
                    result.accepted_events += 1
                elif resp.status_code == 429:
                    result.dropped_events += 1
                else:
                    result.error_events += 1
            except Exception:
                result.error_events += 1
                result.total_events += 1

            if delay > 0:
                await asyncio.sleep(delay)

    result.duration_seconds = duration
    result.throughput_eps = result.accepted_events / duration if duration > 0 else 0
    result.drop_rate_pct = (result.dropped_events / result.total_events * 100) if result.total_events > 0 else 0

    latencies.sort()
    result.latency_p50_ms = _percentile(latencies, 50)
    result.latency_p95_ms = _percentile(latencies, 95)
    result.latency_p99_ms = _percentile(latencies, 99)
    result.latency_min_ms = latencies[0] if latencies else 0
    result.latency_max_ms = latencies[-1] if latencies else 0

    # Get final metrics
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{target}/metrics", headers=headers)
            if resp.status_code == 200:
                metrics = resp.json()
                result.graph_nodes_end = metrics.get("graph", {}).get("node_count", 0)
                result.graph_edges_end = metrics.get("graph", {}).get("edge_count", 0)
        except Exception:
            pass

    return result


def main():
    parser = argparse.ArgumentParser(description="SwarmSentinel Load Test")
    parser.add_argument("--target", default="http://localhost:8000", help="Target server URL")
    parser.add_argument("--rate", type=float, default=50, help="Events per second")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds (HTTP mode)")
    parser.add_argument("--events", type=int, default=1000, help="Total events (in-process mode)")
    parser.add_argument("--in-process", action="store_true", help="Run in-process (no HTTP)")
    parser.add_argument("--api-key", default=os.getenv("API_KEY", "test-api-key"), help="API key")
    parser.add_argument("--output", default=None, help="Output JSON report to file")
    parser.add_argument("--max-nodes", type=int, default=500, help="Graph max nodes (in-process)")
    parser.add_argument("--max-edges", type=int, default=2000, help="Graph max edges (in-process)")
    args = parser.parse_args()

    if args.in_process:
        result = asyncio.run(run_in_process(args.events, args.rate, args.max_nodes, args.max_edges))
    else:
        result = asyncio.run(run_http(args.target, args.rate, args.duration, args.api_key))

    print(result.summary())

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
