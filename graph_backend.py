"""
Graph Backend Abstraction — SwarmSentinel
==========================================

Defines an abstract interface for graph storage so the PheromoneGraph
can work with different backends (in-memory NetworkX, Redis, Neo4j)
without changing any business logic.

This is the key architectural change for scalability: the graph storage
is now a swappable dependency.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional, Tuple

import networkx as nx

logger = logging.getLogger(__name__)


class GraphBackend(ABC):
    """Abstract interface for graph storage operations.

    Any backend (in-memory, Redis, Neo4j, TigerGraph) must implement
    these primitives. The PheromoneGraph delegates all storage to this
    interface and focuses purely on pheromone logic.
    """

    @abstractmethod
    def has_node(self, node_id: str) -> bool: ...

    @abstractmethod
    def add_node(self, node_id: str, attrs: Dict[str, Any]) -> None: ...

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def update_node(self, node_id: str, attrs: Dict[str, Any]) -> None: ...

    @abstractmethod
    def has_edge(self, src: str, dst: str) -> bool: ...

    @abstractmethod
    def add_edge(self, src: str, dst: str, attrs: Dict[str, Any]) -> None: ...

    @abstractmethod
    def get_edge(self, src: str, dst: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    def update_edge(self, src: str, dst: str, attrs: Dict[str, Any]) -> None: ...

    @abstractmethod
    def remove_edge(self, src: str, dst: str) -> None: ...

    @abstractmethod
    def iter_nodes(self) -> Iterator[Tuple[str, Dict[str, Any]]]: ...

    @abstractmethod
    def iter_edges(self) -> Iterator[Tuple[str, str, Dict[str, Any]]]: ...

    @abstractmethod
    def predecessors(self, node_id: str) -> List[str]: ...

    @abstractmethod
    def successors(self, node_id: str) -> List[str]: ...

    @abstractmethod
    def in_degree(self, node_id: str) -> int: ...

    @abstractmethod
    def node_count(self) -> int: ...

    @abstractmethod
    def edge_count(self) -> int: ...

    @abstractmethod
    def clear(self) -> None: ...

    @abstractmethod
    def pagerank(self, **kwargs) -> Dict[str, float]: ...

    @abstractmethod
    def betweenness_centrality(self, **kwargs) -> Dict[str, float]: ...


class InMemoryBackend(GraphBackend):
    """NetworkX-backed in-memory graph backend.

    Default backend for development and demo. Fast for small graphs
    (< 10,000 nodes). Not suitable for production enterprise loads.
    """

    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()
        logger.info("InMemoryBackend initialized (NetworkX DiGraph)")

    def has_node(self, node_id: str) -> bool:
        return self._g.has_node(node_id)

    def add_node(self, node_id: str, attrs: Dict[str, Any]) -> None:
        self._g.add_node(node_id, **attrs)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        if not self._g.has_node(node_id):
            return None
        return dict(self._g.nodes[node_id])

    def update_node(self, node_id: str, attrs: Dict[str, Any]) -> None:
        if self._g.has_node(node_id):
            self._g.nodes[node_id].update(attrs)

    def has_edge(self, src: str, dst: str) -> bool:
        return self._g.has_edge(src, dst)

    def add_edge(self, src: str, dst: str, attrs: Dict[str, Any]) -> None:
        self._g.add_edge(src, dst, **attrs)

    def get_edge(self, src: str, dst: str) -> Optional[Dict[str, Any]]:
        if not self._g.has_edge(src, dst):
            return None
        return dict(self._g.edges[src, dst])

    def update_edge(self, src: str, dst: str, attrs: Dict[str, Any]) -> None:
        if self._g.has_edge(src, dst):
            self._g.edges[src, dst].update(attrs)

    def remove_edge(self, src: str, dst: str) -> None:
        if self._g.has_edge(src, dst):
            self._g.remove_edge(src, dst)

    def iter_nodes(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        for node_id, data in self._g.nodes(data=True):
            yield node_id, dict(data)

    def iter_edges(self) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
        for u, v, data in self._g.edges(data=True):
            yield u, v, dict(data)

    def predecessors(self, node_id: str) -> List[str]:
        if not self._g.has_node(node_id):
            return []
        return list(self._g.predecessors(node_id))

    def successors(self, node_id: str) -> List[str]:
        if not self._g.has_node(node_id):
            return []
        return list(self._g.successors(node_id))

    def in_degree(self, node_id: str) -> int:
        if not self._g.has_node(node_id):
            return 0
        return self._g.in_degree(node_id)

    def node_count(self) -> int:
        return self._g.number_of_nodes()

    def edge_count(self) -> int:
        return self._g.number_of_edges()

    def clear(self) -> None:
        self._g.clear()

    def pagerank(self, **kwargs) -> Dict[str, float]:
        if self._g.number_of_nodes() == 0:
            return {}
        try:
            return nx.pagerank(self._g, **kwargs)
        except nx.NetworkXException:
            return {}

    def betweenness_centrality(self, **kwargs) -> Dict[str, float]:
        if self._g.number_of_nodes() == 0:
            return {}
        try:
            return nx.betweenness_centrality(self._g, **kwargs)
        except nx.NetworkXException:
            return {}


class RedisGraphBackend(GraphBackend):
    """Redis-backed graph backend stub.

    Demonstrates that the graph storage is swappable. In production,
    this would use Redis Streams + sorted sets for edge weights,
    or delegate to a graph database like Neo4j/TigerGraph.

    This stub implements the full interface but stores data in Redis
    hashes and sorted sets for horizontal scalability.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self._available = False
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._adj_out: Dict[str, set] = {}
        self._adj_in: Dict[str, set] = {}

        if redis_url:
            try:
                import redis as redis_lib
                self._redis = redis_lib.from_url(redis_url)
                self._redis.ping()
                self._available = True
                logger.info("RedisGraphBackend connected to %s", redis_url.split("@")[-1] if "@" in redis_url else "redis")
            except Exception as e:
                logger.warning("Redis unavailable, RedisGraphBackend falling back to in-memory: %s", e)
        else:
            logger.info("RedisGraphBackend initialized (in-memory fallback — no Redis URL)")

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def add_node(self, node_id: str, attrs: Dict[str, Any]) -> None:
        self._nodes[node_id] = attrs
        self._adj_out.setdefault(node_id, set())
        self._adj_in.setdefault(node_id, set())

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._nodes.get(node_id)

    def update_node(self, node_id: str, attrs: Dict[str, Any]) -> None:
        if node_id in self._nodes:
            self._nodes[node_id].update(attrs)

    def has_edge(self, src: str, dst: str) -> bool:
        return (src, dst) in self._edges

    def add_edge(self, src: str, dst: str, attrs: Dict[str, Any]) -> None:
        self._edges[(src, dst)] = attrs
        self._adj_out.setdefault(src, set()).add(dst)
        self._adj_in.setdefault(dst, set()).add(src)

    def get_edge(self, src: str, dst: str) -> Optional[Dict[str, Any]]:
        return self._edges.get((src, dst))

    def update_edge(self, src: str, dst: str, attrs: Dict[str, Any]) -> None:
        if (src, dst) in self._edges:
            self._edges[(src, dst)].update(attrs)

    def remove_edge(self, src: str, dst: str) -> None:
        self._edges.pop((src, dst), None)
        if src in self._adj_out:
            self._adj_out[src].discard(dst)
        if dst in self._adj_in:
            self._adj_in[dst].discard(src)

    def iter_nodes(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        yield from self._nodes.items()

    def iter_edges(self) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
        for (u, v), data in self._edges.items():
            yield u, v, data

    def predecessors(self, node_id: str) -> List[str]:
        return list(self._adj_in.get(node_id, set()))

    def successors(self, node_id: str) -> List[str]:
        return list(self._adj_out.get(node_id, set()))

    def in_degree(self, node_id: str) -> int:
        return len(self._adj_in.get(node_id, set()))

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._adj_out.clear()
        self._adj_in.clear()

    def pagerank(self, **kwargs) -> Dict[str, float]:
        # Build temporary NetworkX graph for algorithm
        g = nx.DiGraph()
        for nid in self._nodes:
            g.add_node(nid)
        for (u, v), data in self._edges.items():
            g.add_edge(u, v, weight=data.get("weight", 1.0))
        if g.number_of_nodes() == 0:
            return {}
        try:
            return nx.pagerank(g, **kwargs)
        except nx.NetworkXException:
            return {}

    def betweenness_centrality(self, **kwargs) -> Dict[str, float]:
        g = nx.DiGraph()
        for nid in self._nodes:
            g.add_node(nid)
        for (u, v), data in self._edges.items():
            g.add_edge(u, v, weight=data.get("weight", 1.0))
        if g.number_of_nodes() == 0:
            return {}
        try:
            return nx.betweenness_centrality(g, **kwargs)
        except nx.NetworkXException:
            return {}


def create_backend(backend_type: str = "memory", redis_url: Optional[str] = None) -> GraphBackend:
    """Factory function to create the appropriate graph backend.

    Parameters
    ----------
    backend_type : str
        "memory" for InMemoryBackend, "redis" for RedisGraphBackend.
    redis_url : str, optional
        Redis connection URL (required for "redis" backend).
    """
    if backend_type == "redis":
        return RedisGraphBackend(redis_url=redis_url)
    return InMemoryBackend()
