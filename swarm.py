"""Swarm pheromone publisher — enhanced with PheromoneGraph integration.

Accepts telemetry events, runs them through the detector pipeline,
deposits pheromones into both the legacy flat storage AND the new
NetworkX-based pheromone graph.

The graph enables:
- Multi-hop relationship tracking between entities
- Pheromone decay over time  
- Attack corridor detection
- Ant agent navigation
"""
from typing import Dict, List, Any
import time
import logging

from storage import add_pheromone
from detectors import run_detectors
from swarm_graph import pheromone_graph

logger = logging.getLogger("honeypot.swarm")


def publish_pheromone(event: Dict) -> Dict:
    """Publish a pheromone signal derived from a telemetry event.

    Expected event keys: entity_type, entity_id, score (0-100), evidence (list), ts

    Pipeline:
    1. Run detector pipeline to compute anomaly signals
    2. Enrich base score with detector deltas
    3. Add to legacy flat pheromone storage
    4. Deposit into PheromoneGraph (creates nodes + edges)
    5. Return published event + graph snapshot

    Returns:
        Dict with 'published' (event details) and 'snapshot' (graph state)
    """
    entity_type = event.get("entity_type")
    entity_id = event.get("entity_id")
    base_score = float(event.get("score", 10))
    evidence = event.get("evidence", [])

    if not entity_type or not entity_id:
        raise ValueError("event must contain entity_type and entity_id")

    # Run detectors to compute additional signals
    detector_result = run_detectors(event)
    total_delta = detector_result.get("total_delta", 0)
    signals = detector_result.get("signals", [])

    # Compute enriched score (base + detector deltas, capped at 100)
    enriched_score = min(100, base_score + total_delta)

    ts = event.get("ts") or time.time()

    # ── Legacy flat storage ──
    add_pheromone(entity_type, entity_id, enriched_score, evidence, ts=ts)

    # ── PheromoneGraph integration ──
    node_id = f"{entity_type}:{entity_id}"
    pheromone_graph.add_entity(
        entity_id=node_id,
        entity_type=entity_type,
        metadata={"raw_score": base_score, "enriched_score": enriched_score}
    )

    # Create edges from evidence relationships
    _deposit_graph_edges(node_id, entity_type, evidence, enriched_score, ts)

    logger.info(
        "pheromone_published entity=%s base=%.1f delta=%.1f enriched=%.1f graph_nodes=%d",
        node_id, base_score, total_delta, enriched_score,
        pheromone_graph.graph.number_of_nodes()
    )

    # Log detector signals at info level for visibility
    for signal in signals:
        if signal.get("score_delta", 0) > 0:
            logger.info(
                "  > %s: +%.1f — %s",
                signal["signal_type"], signal["score_delta"], signal["reason"]
            )

    return {
        "published": {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "base_score": base_score,
            "enriched_score": enriched_score,
            "detector_delta": total_delta,
            "detector_signals": signals,
            "evidence": evidence,
            "ts": ts,
        },
        "graph_stats": pheromone_graph.get_stats(),
    }


def _deposit_graph_edges(
    node_id: str,
    entity_type: str,
    evidence: List,
    score: float,
    ts: float,
) -> None:
    """Analyze evidence to create edges between entities in the graph.

    Evidence items may reference other entities (IPs, hosts, users).
    When detected, an edge is created from the current entity to the
    referenced entity, allowing the ant agents to traverse relationships.
    """
    for ev in evidence:
        if not isinstance(ev, dict):
            continue

        ev_type = ev.get("type", "")
        ev_text = ev.get("text", "")
        ev_source = ev.get("source", "detector")

        # Extract entity references from evidence text
        referenced_entities = _extract_entity_refs(ev_text, entity_type, node_id)

        for ref_id, ref_type in referenced_entities:
            ref_node_id = f"{ref_type}:{ref_id}"
            pheromone_graph.add_entity(
                entity_id=ref_node_id,
                entity_type=ref_type,
                metadata={"discovered_via": ev_type}
            )
            pheromone_graph.deposit_pheromone(
                source_id=node_id,
                target_id=ref_node_id,
                signal_type=ev_type,
                strength=score * 0.4,  # Fraction of enriched score
                evidence=ev,
            )


def _extract_entity_refs(text: str, current_type: str, current_id: str) -> List[tuple]:
    """Extract referenced entity (id, type) pairs from evidence text.

    Looks for patterns like IP addresses, hostnames, user emails,
    and domain names mentioned in evidence descriptions.
    """
    import re
    refs = []

    # IP addresses (internal 10.x.x.x or external 185.x.x.x / 91.x.x.x)
    for ip in re.findall(r'\b(?:10|185|91)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text):
        ref_id = f"ip:{ip}"
        if ref_id != current_id:
            refs.append((ip, "ip"))

    # Hostnames (srv-xxx, ws-xxx patterns)
    for host in re.findall(r'\b((?:srv|ws)-[\w-]+)\b', text):
        ref_id = f"host:{host}"
        if ref_id != current_id:
            refs.append((host, "host"))

    # User emails
    for user in re.findall(r'\b([\w.-]+@[\w.-]+\.local)\b', text):
        ref_id = f"user:{user}"
        if ref_id != current_id:
            refs.append((user, "user"))

    # Domains (malicious-looking ones)
    for domain in re.findall(r'\b([\w-]+\.(?:com|net|org|in|xyz|top))\b', text):
        if domain not in ("corp.local",) and not domain.startswith("10."):
            ref_id = f"domain:{domain}"
            if ref_id != current_id:
                refs.append((domain, "domain"))

    # Deduplicate
    seen = set()
    unique = []
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            unique.append(ref)

    return unique


def snapshot() -> List:
    """Return current pheromones from graph (legacy compatibility)."""
    from storage import get_pheromones_snapshot
    return get_pheromones_snapshot()


def graph_snapshot() -> Dict[str, Any]:
    """Return the full pheromone graph snapshot for dashboard."""
    return pheromone_graph.to_snapshot()
