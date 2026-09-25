"""
Pheromone Graph Module — SwarmSentinel
======================================

This module implements a bio-inspired pheromone signalling graph for the
SwarmSentinel honeypot system.  The core idea is borrowed from ant-colony
optimisation: every observed interaction between two network entities
(IP addresses, user accounts, devices, honeypots, hosts) **deposits a
pheromone trail** on a directed edge.  Over time the pheromone decays
exponentially, so only *sustained* or *recent* activity keeps an edge
"hot".

Key concepts
------------
* **Entity (node)** — an IP, user, device, honeypot, or host with
  metadata such as ``entity_type``, ``first_seen``, ``last_seen``, and
  ``total_pheromone`` (sum of all pheromone ever deposited on it).
* **Interaction (edge)** — a directed relationship whose ``weight``
  reflects accumulated pheromone strength.  Each edge also records the
  signal types that contributed to it and any supporting evidence dicts.
* **Decay** — every ``decay_interval`` seconds the system multiplies all
  edge weights and node pheromone totals by ``decay_rate``.  Edges that
  fall below ``min_threshold`` are pruned automatically.
* **Hotspots** — nodes with the highest incoming pheromone, indicating
  entities that are being targeted or are otherwise highly active.
* **Attack corridors** — edges whose weight exceeds a given threshold,
  representing sustained interaction paths that may indicate an ongoing
  attack campaign.

The module exposes a **module-level singleton** ``pheromone_graph`` so
that any part of the application can import and use the shared graph
without manual wiring.
"""

from __future__ import annotations

import logging
import time

from api.logging_utils import logfmt
from collections import deque
from typing import Any, Dict, List, Optional

import networkx as nx

logger = logging.getLogger(__name__)


class PheromoneGraph:
    """NetworkX-backed directed pheromone graph.

    Parameters
    ----------
    decay_rate : float
        Multiplicative factor applied to every edge weight and node
        pheromone total during each decay cycle.  Values closer to 1.0
        mean slower decay.  Default ``0.95``.
    min_threshold : float
        Edges whose weight falls below this value after decay are pruned
        from the graph.  Default ``0.01``.
    decay_interval : float
        Minimum number of seconds between automatic decay sweeps.
        Default ``30.0``.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    MAX_EVIDENCE_PER_EDGE: int = 20

    def __init__(
        self,
        decay_rate: float = 0.95,
        min_threshold: float = 0.01,
        decay_interval: float = 30.0,
        max_nodes: int = 50000,
        max_edges: int = 200000,
    ) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.decay_rate: float = decay_rate
        self.min_threshold: float = min_threshold
        self.decay_interval: float = decay_interval
        self.max_nodes: int = max_nodes
        self.max_edges: int = max_edges
        self._last_decay_time: float = time.time()

        logger.info(
            logfmt(
                "graph_init",
                decay_rate=decay_rate,
                min_threshold=min_threshold,
                decay_interval=decay_interval,
                max_nodes=max_nodes,
                max_edges=max_edges,
            )
        )

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add or update a node in the pheromone graph.

        If the entity already exists its ``last_seen`` timestamp is
        refreshed and any new *metadata* keys are merged (existing keys
        are **not** overwritten so that original observations are
        preserved).

        Parameters
        ----------
        entity_id : str
            Unique identifier for the entity (e.g. an IP address).
        entity_type : str
            Category such as ``"ip"``, ``"user"``, ``"device"``,
            ``"honeypot"``, or ``"host"``.
        metadata : dict, optional
            Arbitrary key/value pairs to store on the node.
        """
        now = time.time()

        if self.graph.has_node(entity_id):
            node_data = self.graph.nodes[entity_id]
            node_data["last_seen"] = now
            # Merge metadata without overwriting existing keys
            if metadata:
                existing_meta: dict = node_data.get("metadata", {})
                for key, value in metadata.items():
                    existing_meta.setdefault(key, value)
                node_data["metadata"] = existing_meta
            logger.debug("Entity updated: %s (type=%s)", entity_id, entity_type)
        else:
            # Enforce node cap — evict lowest-pheromone node if at capacity
            if self.graph.number_of_nodes() >= self.max_nodes:
                self._evict_weakest_node()
            self.graph.add_node(
                entity_id,
                entity_type=entity_type,
                first_seen=now,
                last_seen=now,
                total_pheromone=0.0,
                metadata=metadata or {},
            )
            logger.debug("Entity added: %s (type=%s)", entity_id, entity_type)

    # ------------------------------------------------------------------
    # Pheromone deposit
    # ------------------------------------------------------------------

    def deposit_pheromone(
        self,
        source_id: str,
        target_id: str,
        signal_type: str,
        strength: float,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Deposit pheromone on the directed edge ``source → target``.

        If either endpoint does not yet exist it is auto-created with
        ``entity_type="unknown"``.

        When the edge already exists a **reinforcement** formula is used
        so that repeated signals strengthen the trail without unbounded
        growth::

            new_weight = old_weight * 0.7 + strength * 0.3

        The edge also accumulates the list of contributing
        ``signal_types`` and ``evidence`` dicts, along with a
        ``reinforcement_count``.

        The *target* node's ``total_pheromone`` is incremented by
        ``strength`` to support hotspot detection.

        Parameters
        ----------
        source_id : str
            Origin entity of the interaction.
        target_id : str
            Destination entity of the interaction.
        signal_type : str
            Category of the signal (e.g. ``"login_attempt"``,
            ``"port_scan"``).
        strength : float
            Raw pheromone value to deposit.  Positive values expected.
        evidence : dict, optional
            Supporting evidence payload to attach to the edge.
        """
        # Auto-create missing nodes
        if not self.graph.has_node(source_id):
            self.add_entity(source_id, entity_type="unknown")
            logger.debug("Auto-created source entity: %s", source_id)
        if not self.graph.has_node(target_id):
            self.add_entity(target_id, entity_type="unknown")
            logger.debug("Auto-created target entity: %s", target_id)

        now = time.time()

        if self.graph.has_edge(source_id, target_id):
            edge_data = self.graph.edges[source_id, target_id]
            old_weight: float = edge_data.get("weight", 0.0)
            edge_data["weight"] = old_weight * 0.7 + strength * 0.3
            edge_data["last_updated"] = now

            # Append signal type if not already tracked
            signal_types: List[str] = edge_data.get("signal_types", [])
            if signal_type not in signal_types:
                signal_types.append(signal_type)
            edge_data["signal_types"] = signal_types

            # Append evidence (bounded FIFO)
            if evidence is not None:
                evidence_list: List[Dict[str, Any]] = edge_data.get("evidence", [])
                evidence_list.append(evidence)
                if len(evidence_list) > self.MAX_EVIDENCE_PER_EDGE:
                    evidence_list = evidence_list[-self.MAX_EVIDENCE_PER_EDGE:]
                edge_data["evidence"] = evidence_list

            edge_data["reinforcement_count"] = edge_data.get("reinforcement_count", 1) + 1

            logger.debug(
                "Pheromone reinforced on %s → %s: %.4f → %.4f",
                source_id,
                target_id,
                old_weight,
                edge_data["weight"],
            )
        else:
            # Enforce edge cap — evict weakest edge if at capacity
            if self.graph.number_of_edges() >= self.max_edges:
                self._evict_weakest_edge()
            self.graph.add_edge(
                source_id,
                target_id,
                weight=strength,
                signal_types=[signal_type],
                evidence=[evidence] if evidence is not None else [],
                reinforcement_count=1,
                first_created=now,
                last_updated=now,
            )
            logger.debug(
                "Pheromone deposited on new edge %s → %s: %.4f",
                source_id,
                target_id,
                strength,
            )

        # Accumulate pheromone on the target node
        self.graph.nodes[target_id]["total_pheromone"] = (
            self.graph.nodes[target_id].get("total_pheromone", 0.0) + strength
        )

        # Refresh last_seen on both endpoints
        self.graph.nodes[source_id]["last_seen"] = now
        self.graph.nodes[target_id]["last_seen"] = now

    # ------------------------------------------------------------------
    # Decay
    # ------------------------------------------------------------------

    def decay_all(self) -> int:
        """Apply exponential decay to every edge weight and node pheromone.

        Edges whose weight drops below ``min_threshold`` are removed
        from the graph.

        Returns
        -------
        int
            Number of edges pruned during this decay cycle.
        """
        self._last_decay_time = time.time()
        edges_to_remove: List[tuple] = []

        for u, v, data in self.graph.edges(data=True):
            data["weight"] *= self.decay_rate
            if data["weight"] < self.min_threshold:
                edges_to_remove.append((u, v))

        # Decay node-level pheromone totals
        for _, node_data in self.graph.nodes(data=True):
            node_data["total_pheromone"] = node_data.get("total_pheromone", 0.0) * self.decay_rate

        # Prune weak edges
        pruned_edges = len(edges_to_remove)
        for u, v in edges_to_remove:
            self.graph.remove_edge(u, v)

        # Prune orphan nodes (no edges and negligible pheromone)
        orphans = [
            n for n in list(self.graph.nodes)
            if self.graph.in_degree(n) == 0
            and self.graph.out_degree(n) == 0
            and self.graph.nodes[n].get("total_pheromone", 0.0) < self.min_threshold
        ]
        for n in orphans:
            self.graph.remove_node(n)

        logger.info(
            logfmt(
                "decay_sweep",
                edges_pruned=pruned_edges,
                orphans_pruned=len(orphans),
                nodes=self.graph.number_of_nodes(),
                edges=self.graph.number_of_edges(),
            )
        )

        return pruned_edges

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_hotspots(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Return the top-N nodes ranked by total incoming pheromone weight.

        Each entry is a dict with keys ``entity_id``, ``entity_type``,
        ``total_pheromone``, ``incoming_edges``, and ``metadata``.

        Parameters
        ----------
        top_n : int
            Maximum number of hotspots to return.  Default ``10``.
        """
        hotspots: List[Dict[str, Any]] = []

        for node_id, node_data in self.graph.nodes(data=True):
            # Sum weights of all incoming edges
            incoming_weight = sum(
                self.graph.edges[u, node_id].get("weight", 0.0)
                for u in self.graph.predecessors(node_id)
            )
            incoming_edge_count = self.graph.in_degree(node_id)

            hotspots.append(
                {
                    "entity_id": node_id,
                    "entity_type": node_data.get("entity_type", "unknown"),
                    "total_pheromone": node_data.get("total_pheromone", 0.0),
                    "incoming_edges": incoming_edge_count,
                    "metadata": node_data.get("metadata", {}),
                }
            )

        # Sort descending by total incoming pheromone weight
        hotspots.sort(key=lambda h: h["total_pheromone"], reverse=True)
        return hotspots[:top_n]

    def get_attack_corridors(
        self, min_strength: float = 0.5
    ) -> List[Dict[str, Any]]:
        """Identify edges with high cumulative pheromone ("attack corridors").

        Returns every edge whose weight is at or above *min_strength*,
        sorted descending by weight.

        Parameters
        ----------
        min_strength : float
            Minimum edge weight to qualify as a corridor.  Default
            ``0.5``.

        Returns
        -------
        list of dict
            Each dict contains ``source``, ``target``, ``weight``,
            ``signal_types``, and ``evidence``.
        """
        corridors: List[Dict[str, Any]] = []

        for u, v, data in self.graph.edges(data=True):
            weight: float = data.get("weight", 0.0)
            if weight >= min_strength:
                corridors.append(
                    {
                        "source": u,
                        "target": v,
                        "weight": weight,
                        "signal_types": data.get("signal_types", []),
                        "evidence": data.get("evidence", []),
                    }
                )

        corridors.sort(key=lambda c: c["weight"], reverse=True)
        return corridors

    def get_neighbors(
        self, entity_id: str, min_strength: float = 0.1
    ) -> List[Dict[str, Any]]:
        """Get entities connected to *entity_id* with sufficient edge weight.

        Both predecessors (incoming edges) and successors (outgoing
        edges) are included.

        Parameters
        ----------
        entity_id : str
            Node to query.
        min_strength : float
            Minimum edge weight to include a neighbor.  Default ``0.1``.

        Returns
        -------
        list of dict
            Each dict has ``entity_id``, ``entity_type``,
            ``edge_weight``, and ``direction`` (``"incoming"`` or
            ``"outgoing"``).
        """
        if not self.graph.has_node(entity_id):
            logger.warning(logfmt("graph_unknown_neighbors", entity_id=entity_id))
            return []

        neighbors: List[Dict[str, Any]] = []

        # Outgoing edges (entity → neighbor)
        for successor in self.graph.successors(entity_id):
            weight: float = self.graph.edges[entity_id, successor].get("weight", 0.0)
            if weight >= min_strength:
                neighbors.append(
                    {
                        "entity_id": successor,
                        "entity_type": self.graph.nodes[successor].get(
                            "entity_type", "unknown"
                        ),
                        "edge_weight": weight,
                        "direction": "outgoing",
                    }
                )

        # Incoming edges (neighbor → entity)
        for predecessor in self.graph.predecessors(entity_id):
            weight = self.graph.edges[predecessor, entity_id].get("weight", 0.0)
            if weight >= min_strength:
                neighbors.append(
                    {
                        "entity_id": predecessor,
                        "entity_type": self.graph.nodes[predecessor].get(
                            "entity_type", "unknown"
                        ),
                        "edge_weight": weight,
                        "direction": "incoming",
                    }
                )

        neighbors.sort(key=lambda n: n["edge_weight"], reverse=True)
        return neighbors

    def get_subgraph(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Extract a serialisable subgraph via BFS from *entity_id*.

        Parameters
        ----------
        entity_id : str
            Starting node for the traversal.
        depth : int
            Maximum number of hops from the starting node.  Default
            ``2``.

        Returns
        -------
        dict
            A JSON-friendly dict with ``nodes`` and ``edges`` lists.
        """
        if not self.graph.has_node(entity_id):
            logger.warning(logfmt("graph_unknown_subgraph", entity_id=entity_id))
            return {"nodes": [], "edges": []}

        visited: set = set()
        queue: deque = deque()
        queue.append((entity_id, 0))
        visited.add(entity_id)

        while queue:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            # Follow both directions
            for neighbor in self.graph.successors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, current_depth + 1))
            for neighbor in self.graph.predecessors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, current_depth + 1))

        # Build serialisable output
        nodes: List[Dict[str, Any]] = []
        for node_id in visited:
            nd = self.graph.nodes[node_id]
            nodes.append(
                {
                    "id": node_id,
                    "type": nd.get("entity_type", "unknown"),
                    "pheromone": nd.get("total_pheromone", 0.0),
                    "first_seen": nd.get("first_seen"),
                    "last_seen": nd.get("last_seen"),
                    "metadata": nd.get("metadata", {}),
                }
            )

        edges: List[Dict[str, Any]] = []
        for u, v, data in self.graph.edges(data=True):
            if u in visited and v in visited:
                edges.append(
                    {
                        "source": u,
                        "target": v,
                        "weight": data.get("weight", 0.0),
                        "signal_types": data.get("signal_types", []),
                        "reinforcement_count": data.get("reinforcement_count", 0),
                    }
                )

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Snapshot / stats
    # ------------------------------------------------------------------

    def to_snapshot(self) -> Dict[str, Any]:
        """Serialise the full graph for WebSocket broadcast to the dashboard.

        Returns
        -------
        dict
            ``{nodes, edges, stats}`` where each list entry is a plain
            dict safe for ``json.dumps``.
        """
        nodes: List[Dict[str, Any]] = []
        for node_id, nd in self.graph.nodes(data=True):
            nodes.append(
                {
                    "id": node_id,
                    "type": nd.get("entity_type", "unknown"),
                    "pheromone": nd.get("total_pheromone", 0.0),
                    "first_seen": nd.get("first_seen"),
                    "last_seen": nd.get("last_seen"),
                    "metadata": nd.get("metadata", {}),
                }
            )

        edges: List[Dict[str, Any]] = []
        for u, v, data in self.graph.edges(data=True):
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "weight": data.get("weight", 0.0),
                    "signal_types": data.get("signal_types", []),
                    "reinforcement_count": data.get("reinforcement_count", 0),
                    "last_updated": data.get("last_updated"),
                }
            )

        total_pheromone = sum(
            nd.get("total_pheromone", 0.0) for _, nd in self.graph.nodes(data=True)
        )
        hotspot_count = sum(
            1
            for _, nd in self.graph.nodes(data=True)
            if nd.get("total_pheromone", 0.0) > 0.5
        )

        stats = {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "total_pheromone": total_pheromone,
            "hotspot_count": hotspot_count,
        }

        return {"nodes": nodes, "edges": edges, "stats": stats}

    def get_stats(self) -> Dict[str, Any]:
        """Return quick summary statistics about the graph.

        Returns
        -------
        dict
            Keys: ``node_count``, ``edge_count``, ``total_pheromone``,
            ``avg_edge_weight``, ``max_edge_weight``.
        """
        edge_weights: List[float] = [
            data.get("weight", 0.0) for _, _, data in self.graph.edges(data=True)
        ]
        total_pheromone = sum(
            nd.get("total_pheromone", 0.0) for _, nd in self.graph.nodes(data=True)
        )

        node_count = self.graph.number_of_nodes()
        edge_count = self.graph.number_of_edges()
        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "node_utilization_pct": round(node_count / self.max_nodes * 100, 1) if self.max_nodes else 0.0,
            "edge_utilization_pct": round(edge_count / self.max_edges * 100, 1) if self.max_edges else 0.0,
            "total_pheromone": total_pheromone,
            "avg_edge_weight": (
                sum(edge_weights) / len(edge_weights) if edge_weights else 0.0
            ),
            "max_edge_weight": max(edge_weights) if edge_weights else 0.0,
            "last_decay_time": self._last_decay_time,
        }

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Remove all nodes and edges from the graph (useful for testing)."""
        self.graph.clear()
        self._last_decay_time = time.time()
        logger.info(logfmt("graph_cleared", node_count=0, edge_count=0))

    def reset_state(self) -> None:
        """Explicit reset hook for tests, demos, and API reset flows."""
        self.clear()

    # ------------------------------------------------------------------
    # Eviction helpers (cap enforcement)
    # ------------------------------------------------------------------

    def _evict_weakest_node(self) -> None:
        """Remove the node with the lowest total_pheromone to stay within cap."""
        if not self.graph.nodes:
            return
        weakest = min(
            self.graph.nodes,
            key=lambda n: self.graph.nodes[n].get("total_pheromone", 0.0),
        )
        self.graph.remove_node(weakest)
        logger.info(logfmt("graph_evict_node", node=weakest, reason="max_nodes_cap"))

    def _evict_weakest_edge(self) -> None:
        """Remove the edge with the lowest weight to stay within cap."""
        if not self.graph.edges:
            return
        weakest_u, weakest_v = min(
            self.graph.edges,
            key=lambda e: self.graph.edges[e].get("weight", 0.0),
        )
        self.graph.remove_edge(weakest_u, weakest_v)
        logger.debug(logfmt("graph_evict_edge", source=weakest_u, target=weakest_v, reason="max_edges_cap"))

    # ------------------------------------------------------------------
    # Predictive scoring (Innovation)
    # ------------------------------------------------------------------

    def predict_next_targets(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """Predict which entities are most likely to be targeted next.

        Uses a combination of PageRank (identifies structurally important
        nodes that many attack paths flow through) and betweenness
        centrality (identifies bridge nodes connecting different attack
        clusters).

        This is a genuine algorithmic advantage over threshold-based
        SIEM systems — it uses the *topology* of the attack graph to
        predict future movement, not just current scores.

        Parameters
        ----------
        top_n : int
            Number of predictions to return.

        Returns
        -------
        list of dict
            Each dict has ``entity_id``, ``entity_type``,
            ``risk_score``, ``pagerank``, ``betweenness``,
            ``current_pheromone``, and ``reason``.
        """
        if self.graph.number_of_nodes() < 2:
            return []

        try:
            pr = nx.pagerank(self.graph, weight="weight")
        except nx.NetworkXException:
            pr = {}

        try:
            bc = nx.betweenness_centrality(self.graph, weight="weight")
        except nx.NetworkXException:
            bc = {}

        predictions = []
        for node_id, node_data in self.graph.nodes(data=True):
            current_ph = node_data.get("total_pheromone", 0.0)
            pr_score = pr.get(node_id, 0.0)
            bc_score = bc.get(node_id, 0.0)

            # Combined risk: high PageRank + high betweenness + low current pheromone
            # = node that is structurally critical but hasn't been hit hard yet
            # These are the most dangerous — the attacker will likely pass through them
            structural_importance = (pr_score * 1000 + bc_score * 500)
            if current_ph < 10:  # not yet a hotspot — higher risk of being next
                structural_importance *= 1.5

            if structural_importance < 0.1:
                continue

            reasons = []
            if pr_score > 0.1:
                reasons.append("High PageRank — many attack paths converge here")
            if bc_score > 0.05:
                reasons.append("High betweenness — bridge node between attack clusters")
            if current_ph < 5 and structural_importance > 1:
                reasons.append("Low pheromone but structurally critical — likely next target")

            predictions.append({
                "entity_id": node_id,
                "entity_type": node_data.get("entity_type", "unknown"),
                "risk_score": round(structural_importance, 2),
                "pagerank": round(pr_score, 4),
                "betweenness": round(bc_score, 4),
                "current_pheromone": round(current_ph, 1),
                "reason": "; ".join(reasons) if reasons else "Moderate structural risk",
            })

        predictions.sort(key=lambda p: p["risk_score"], reverse=True)
        return predictions[:top_n]

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"PheromoneGraph(nodes={self.graph.number_of_nodes()}, "
            f"edges={self.graph.number_of_edges()}, "
            f"decay_rate={self.decay_rate})"
        )


# ----------------------------------------------------------------------
# Module-level singleton
# ----------------------------------------------------------------------

pheromone_graph: PheromoneGraph = PheromoneGraph()
"""Pre-configured singleton instance for application-wide use."""
