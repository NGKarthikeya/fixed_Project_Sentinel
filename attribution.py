"""Email indicator attribution into the SwarmSentinel pheromone graph."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from itertools import combinations
from typing import Any

from event_queue import event_queue
from schemas import Evidence, TelemetryEvent

logger = logging.getLogger(__name__)

_INDICATOR_TYPES: dict[str, str] = {
    "domains": "email_domain",
    "ips": "email_ip",
    "asns": "asn",
    "upi_ids": "upi_id",
    "reply_tos": "reply_to",
}


def _normalise_indicators(indicators: dict[str, list[str]]) -> list[tuple[str, str]]:
    if not isinstance(indicators, dict):
        raise TypeError("indicators must be a dictionary")

    nodes: list[tuple[str, str]] = []
    for key, entity_type in _INDICATOR_TYPES.items():
        values = indicators.get(key, [])
        if values is None:
            continue
        if not isinstance(values, list):
            raise TypeError(f"indicators[{key!r}] must be a list of strings")
        for value in values:
            if not isinstance(value, str):
                raise TypeError(f"indicators[{key!r}] must contain only strings")
            normalized = value.strip()
            if normalized and (entity_type, normalized) not in nodes:
                nodes.append((entity_type, normalized))
    return nodes


def _enqueue(event: TelemetryEvent) -> None:
    """Submit telemetry without requiring callers to become async."""
    coroutine = event_queue.enqueue(event.model_dump())
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        try:
            asyncio.run(coroutine)
        except Exception as exc:
            logger.warning("Email attribution telemetry could not be queued: %s", exc)
        return

    task = loop.create_task(coroutine)
    task.add_done_callback(_log_queue_failure)


def _log_queue_failure(task: asyncio.Task[bool]) -> None:
    try:
        if not task.result():
            logger.warning("Email attribution telemetry was rejected by queue backpressure.")
    except Exception as exc:
        logger.warning("Email attribution telemetry could not be queued: %s", exc)


def _record_node(graph_client: Any, node_id: str, entity_type: str, email_id: str) -> None:
    now = time.time()
    if hasattr(graph_client, "add_entity"):
        graph_client.add_entity(
            entity_id=node_id,
            entity_type=entity_type,
            metadata={"last_email_id": email_id},
        )
    elif hasattr(graph_client, "add_node"):
        existing = graph_client.get_node(node_id) or {}
        existing_meta = existing.get("metadata", {})
        existing_meta["last_email_id"] = email_id
        graph_client.add_node(
            node_id,
            {
                "entity_type": entity_type,
                "first_seen": existing.get("first_seen", now),
                "last_seen": now,
                "total_pheromone": float(existing.get("total_pheromone", 0.0)),
                "metadata": existing_meta,
            },
        )

    if hasattr(graph_client, "graph") and graph_client.graph.has_node(node_id):
        node = graph_client.graph.nodes[node_id]
        metadata = node.setdefault("metadata", {})
        metadata["last_email_id"] = email_id
        metadata["observation_count"] = int(metadata.get("observation_count", 0)) + 1
        node["last_seen"] = now
        node["total_pheromone"] = float(node.get("total_pheromone", 0.0)) + 1.0
    elif hasattr(graph_client, "get_node") and hasattr(graph_client, "update_node"):
        node = graph_client.get_node(node_id) or {}
        metadata = node.setdefault("metadata", {})
        metadata["last_email_id"] = email_id
        metadata["observation_count"] = int(metadata.get("observation_count", 0)) + 1
        node["last_seen"] = now
        node["total_pheromone"] = float(node.get("total_pheromone", 0.0)) + 1.0
        graph_client.update_node(node_id, node)


def _record_edge(graph_client: Any, source: str, target: str) -> None:
    now = time.time()
    now_utc = datetime.now(timezone.utc)
    if hasattr(graph_client, "graph"):
        if graph_client.graph.has_edge(source, target):
            edge = graph_client.graph.edges[source, target]
            edge["weight"] = float(edge.get("weight", 0.0)) + 1.0
            edge["reinforcement_count"] = int(edge.get("reinforcement_count", 0)) + 1
            signal_types = edge.setdefault("signal_types", [])
            if "email_campaign" not in signal_types:
                signal_types.append("email_campaign")
            edge["last_updated"] = now
            edge["last_seen"] = now_utc
            return

        graph_client.graph.add_edge(
            source,
            target,
            weight=1.0,
            signal_types=["email_campaign"],
            evidence=[],
            reinforcement_count=1,
            first_created=now,
            last_updated=now,
            last_seen=now_utc,
        )
    elif hasattr(graph_client, "has_edge") and hasattr(graph_client, "add_edge"):
        if graph_client.has_edge(source, target):
            edge = graph_client.get_edge(source, target) or {}
            edge["weight"] = float(edge.get("weight", 0.0)) + 1.0
            edge["reinforcement_count"] = int(edge.get("reinforcement_count", 0)) + 1
            signal_types = edge.setdefault("signal_types", [])
            if "email_campaign" not in signal_types:
                signal_types.append("email_campaign")
            edge["last_updated"] = now
            edge["last_seen"] = now_utc
            graph_client.update_edge(source, target, edge)
            return

        graph_client.add_edge(
            source,
            target,
            {
                "weight": 1.0,
                "signal_types": ["email_campaign"],
                "evidence": [],
                "reinforcement_count": 1,
                "first_created": now,
                "last_updated": now,
                "last_seen": now_utc,
            },
        )


def record_email_attribution(
    email_id: str,
    indicators: dict[str, list[str]],
    graph_client: Any,
) -> list[str]:
    """Record one email's indicators and their campaign co-occurrence graph."""
    if not isinstance(email_id, str) or not email_id.strip():
        raise ValueError("email_id must be a non-empty string")
    if not (hasattr(graph_client, "add_entity") or hasattr(graph_client, "add_node")):
        raise TypeError("graph_client must expose add_entity/add_node and graph storage methods")

    normalized_nodes = _normalise_indicators(indicators)
    affected_ids: list[str] = []
    for entity_type, value in normalized_nodes:
        node_id = f"{entity_type}:{value}"
        _record_node(graph_client, node_id, entity_type, email_id.strip())
        affected_ids.append(node_id)

        event = TelemetryEvent(
            entity_type=entity_type,
            entity_id=value,
            score=10.0,
            evidence=[Evidence(type="email_attribution", text=email_id.strip(), source="email_analysis")],
            ts=time.time(),
        )
        _enqueue(event)

    node_ids = [f"{entity_type}:{value}" for entity_type, value in normalized_nodes]
    for source, target in combinations(node_ids, 2):
        _record_edge(graph_client, source, target)
        _record_edge(graph_client, target, source)

    return affected_ids

