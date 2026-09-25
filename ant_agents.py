"""
Ant Agent System for SwarmSentinel.

Bio-inspired agents that traverse the pheromone graph to detect, investigate,
and respond to threats. Three agent types form a hierarchy:

- ScoutAnt: Lightweight, fast probers. Many instances patrol the network,
  collect micro-signals, and deposit low-strength pheromone trails.
- SoldierAnt: Triggered when pheromone concentration crosses a threshold.
  Deep-inspects flagged entities, correlates with honeypot data, builds
  attack chains.
- QueenAgent: Singleton coordinator. Reads the full pheromone graph,
  identifies clusters and corridors, runs global pattern recognition,
  and issues directives to soldiers and the SOAR/policy engine.

The SwarmCoordinator manages all agent lifecycles and the decay timer.
"""

import asyncio
import time
import uuid
import logging
import random
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger("honeypot.ants")


# ── Scout Ant ──────────────────────────────────────────────────────────

class ScoutAnt:
    """
    Lightweight agent that patrols network entities and deposits
    pheromone trails when anomalies are found.
    
    Behavior:
    - Random walk with pheromone-biased direction
    - Probes entities for micro-signals (small anomalies)
    - Deposits low-strength pheromone on suspicious paths
    - Reports findings back to the SwarmCoordinator
    """

    def __init__(self, ant_id: str = None, probe_interval: float = 3.0):
        self.ant_id = ant_id or f"scout-{uuid.uuid4().hex[:8]}"
        self.ant_type = "scout"
        self.state = "idle"
        self.current_entity: Optional[str] = None
        self.probe_interval = probe_interval
        self.pheromones_deposited = 0
        self.anomalies_found = 0
        self.last_active = time.time()
        self.findings: List[Dict[str, Any]] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self, graph, coordinator: "SwarmCoordinator"):
        """Start the scout's patrol loop."""
        self._running = True
        self.state = "probing"
        logger.info(f"🐜 Scout {self.ant_id} started patrol")
        
        while self._running:
            try:
                await self._patrol_step(graph, coordinator)
                await asyncio.sleep(self.probe_interval + random.uniform(-0.5, 1.0))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scout {self.ant_id} error: {e}", exc_info=True)
                await asyncio.sleep(2.0)
        
        self.state = "idle"
        logger.info(f"🐜 Scout {self.ant_id} stopped")

    async def _patrol_step(self, graph, coordinator: "SwarmCoordinator"):
        """Execute one patrol step: pick entity, probe, deposit pheromone if suspicious."""
        self.last_active = time.time()
        
        # Choose next entity to probe (pheromone-biased random walk)
        target = self._choose_target(graph)
        if not target:
            return
        
        self.current_entity = target
        self.state = "probing"
        
        # Probe the entity for anomalies
        anomaly = self._probe_entity(target, graph)
        
        if anomaly and anomaly["score_delta"] > 0:
            self.anomalies_found += 1
            
            # Deposit pheromone trail
            source_entity = anomaly.get("related_entity", f"scout:{self.ant_id}")
            graph.deposit_pheromone(
                source_id=source_entity,
                target_id=target,
                signal_type=anomaly["signal_type"],
                strength=anomaly["score_delta"] * 0.3,  # Scouts deposit low-strength
                evidence=anomaly.get("evidence", {})
            )
            self.pheromones_deposited += 1
            
            finding = {
                "ant_id": self.ant_id,
                "entity": target,
                "anomaly": anomaly,
                "timestamp": time.time()
            }
            self.findings.append(finding)
            
            # Notify coordinator if pheromone is building up
            node_data = graph.graph.nodes.get(target, {})
            total_ph = node_data.get("total_pheromone", 0)
            if total_ph > coordinator.soldier_threshold:
                await coordinator.request_soldier(target, f"Pheromone concentration {total_ph:.1f} exceeds threshold")
            
            logger.info(
                f"🐜 Scout {self.ant_id}: anomaly at {target} "
                f"type={anomaly['signal_type']} delta={anomaly['score_delta']:.1f}"
            )

    def _choose_target(self, graph) -> Optional[str]:
        """
        Choose next entity to probe using pheromone-biased random walk.
        Higher pheromone = higher probability of being selected.
        """
        nodes = list(graph.graph.nodes())
        if not nodes:
            return None
        
        if len(nodes) <= 3:
            return random.choice(nodes)
        
        # Pheromone-biased selection: nodes with more pheromone get higher weight
        weights = []
        for node in nodes:
            ph = graph.graph.nodes[node].get("total_pheromone", 0)
            # Base weight + pheromone bonus (so even low-pheromone nodes get visited)
            weights.append(1.0 + ph * 2.0)
        
        total_weight = sum(weights)
        if total_weight == 0:
            return random.choice(nodes)
        
        # Weighted random selection
        r = random.uniform(0, total_weight)
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return nodes[i]
        
        return nodes[-1]

    def _probe_entity(self, entity_id: str, graph) -> Optional[Dict[str, Any]]:
        """
        Probe an entity for anomalous signals.
        Checks: incoming pheromone patterns, edge diversity, timing anomalies.
        """
        node_data = graph.graph.nodes.get(entity_id, {})
        if not node_data:
            return None
        
        total_ph = node_data.get("total_pheromone", 0)
        entity_type = node_data.get("entity_type", "unknown")
        
        # Check incoming edges for suspicious patterns
        in_edges = list(graph.graph.in_edges(entity_id, data=True))
        out_edges = list(graph.graph.out_edges(entity_id, data=True))
        
        # Anomaly 1: High incoming pheromone from multiple sources
        if len(in_edges) >= 3:
            avg_weight = sum(d.get("weight", 0) for _, _, d in in_edges) / len(in_edges)
            if avg_weight > 5.0:
                return {
                    "signal_type": "convergence",
                    "score_delta": min(30, avg_weight * 2),
                    "related_entity": in_edges[0][0],  # first source
                    "evidence": {
                        "type": "convergence_pattern",
                        "text": f"Entity {entity_id} receiving pheromone from {len(in_edges)} sources (avg weight: {avg_weight:.1f})",
                        "source": f"scout:{self.ant_id}"
                    }
                }
        
        # Anomaly 2: Rapid pheromone accumulation (entity recently appeared but high pheromone)
        first_seen = node_data.get("first_seen", time.time())
        age = time.time() - first_seen
        if age < 60 and total_ph > 10:  # Less than 1 minute old but significant pheromone
            return {
                "signal_type": "rapid_accumulation",
                "score_delta": min(25, total_ph),
                "evidence": {
                    "type": "timing_anomaly",
                    "text": f"Entity {entity_id} accumulated {total_ph:.1f} pheromone in {age:.0f}s",
                    "source": f"scout:{self.ant_id}"
                }
            }
        
        # Anomaly 3: Entity has both in and out edges (potential pivot point)
        if len(in_edges) >= 1 and len(out_edges) >= 1:
            pivot_score = (len(in_edges) + len(out_edges)) * 3
            if pivot_score > 10:
                return {
                    "signal_type": "pivot_point",
                    "score_delta": min(20, pivot_score),
                    "related_entity": in_edges[0][0],
                    "evidence": {
                        "type": "pivot_pattern",
                        "text": f"Entity {entity_id} has {len(in_edges)} inbound and {len(out_edges)} outbound connections",
                        "source": f"scout:{self.ant_id}"
                    }
                }
        
        return None

    def stop(self):
        """Stop the scout's patrol."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    def to_status(self) -> Dict[str, Any]:
        """Return serializable status."""
        return {
            "ant_id": self.ant_id,
            "ant_type": self.ant_type,
            "state": self.state,
            "current_entity": self.current_entity,
            "pheromones_deposited": self.pheromones_deposited,
            "anomalies_found": self.anomalies_found,
            "last_active": self.last_active,
            "findings_count": len(self.findings),
        }


# ── Soldier Ant ────────────────────────────────────────────────────────

class SoldierAnt:
    """
    Deep-inspection agent triggered when pheromone concentration
    crosses a threshold. Correlates with honeypot data, builds
    detailed attack chains, and deposits high-strength pheromone.
    """

    def __init__(self, ant_id: str = None):
        self.ant_id = ant_id or f"soldier-{uuid.uuid4().hex[:8]}"
        self.ant_type = "soldier"
        self.state = "idle"
        self.current_entity: Optional[str] = None
        self.pheromones_deposited = 0
        self.anomalies_found = 0
        self.last_active = time.time()
        self.findings: List[Dict[str, Any]] = []
        self.investigation_history: List[str] = []

    async def investigate(self, target_entity: str, reason: str, graph, coordinator: "SwarmCoordinator"):
        """
        Deep-inspect a flagged entity.
        
        1. Analyze all edges and evidence connected to the entity
        2. Build local attack chain
        3. Deposit high-strength pheromone with detailed evidence
        4. Report findings to the coordinator
        """
        self.state = "investigating"
        self.current_entity = target_entity
        self.last_active = time.time()
        self.investigation_history.append(target_entity)
        
        logger.info(f"🐝 Soldier {self.ant_id}: investigating {target_entity} — {reason}")
        
        # Phase 1: Gather all evidence from the entity's neighborhood
        subgraph = graph.get_subgraph(target_entity, depth=2)
        neighbors = graph.get_neighbors(target_entity, min_strength=0.05)
        
        # Phase 2: Analyze attack patterns
        attack_analysis = self._analyze_attack_pattern(target_entity, subgraph, neighbors, graph)
        
        # Phase 3: Deposit high-strength pheromone on attack corridors
        if attack_analysis["threat_level"] > 0.3:
            self.anomalies_found += 1
            
            for corridor in attack_analysis.get("corridors", []):
                graph.deposit_pheromone(
                    source_id=corridor["source"],
                    target_id=corridor["target"],
                    signal_type="soldier_confirmed",
                    strength=attack_analysis["threat_level"] * 50,  # High-strength deposit
                    evidence={
                        "type": "soldier_investigation",
                        "text": f"Soldier confirmed threat corridor: {corridor['source']} → {corridor['target']}",
                        "source": f"soldier:{self.ant_id}",
                        "threat_level": attack_analysis["threat_level"],
                        "attack_type": attack_analysis.get("attack_type", "unknown")
                    }
                )
                self.pheromones_deposited += 1
            
            finding = {
                "ant_id": self.ant_id,
                "entity": target_entity,
                "threat_level": attack_analysis["threat_level"],
                "attack_type": attack_analysis.get("attack_type", "unknown"),
                "entities_involved": attack_analysis.get("entities_involved", []),
                "evidence_count": attack_analysis.get("evidence_count", 0),
                "corridors": attack_analysis.get("corridors", []),
                "timestamp": time.time()
            }
            self.findings.append(finding)
            
            # Report to coordinator for potential incident creation
            await coordinator.soldier_report(finding)
            
            logger.warning(
                f"🐝 Soldier {self.ant_id}: CONFIRMED THREAT at {target_entity} "
                f"level={attack_analysis['threat_level']:.2f} "
                f"type={attack_analysis.get('attack_type', 'unknown')}"
            )
        else:
            logger.info(f"🐝 Soldier {self.ant_id}: {target_entity} appears benign (level={attack_analysis['threat_level']:.2f})")
        
        self.state = "idle"
        self.current_entity = None
        return attack_analysis

    def _analyze_attack_pattern(self, entity_id: str, subgraph: dict, neighbors: list, graph) -> Dict[str, Any]:
        """
        Analyze the entity's neighborhood for attack patterns.
        Returns threat assessment with identified corridors and attack type.
        """
        nodes = subgraph.get("nodes", [])
        edges = subgraph.get("edges", [])
        
        # Collect all evidence from edges
        all_evidence = []
        total_edge_weight = 0
        corridors = []
        
        for edge in edges:
            weight = edge.get("weight", 0)
            total_edge_weight += weight
            evidence_list = edge.get("evidence", [])
            all_evidence.extend(evidence_list)
            
            if weight > 5.0:
                corridors.append({
                    "source": edge.get("source", ""),
                    "target": edge.get("target", ""),
                    "weight": weight
                })
        
        # Determine attack type from evidence
        attack_type = self._classify_attack(all_evidence)
        
        # Calculate threat level based on:
        # - Number of connected entities
        # - Total edge weight
        # - Evidence diversity
        # - Presence of high-weight corridors
        entity_count = len(nodes)
        evidence_types = set()
        for ev in all_evidence:
            if isinstance(ev, dict):
                evidence_types.add(ev.get("type", "unknown"))
        
        threat_factors = {
            "entity_density": min(1.0, entity_count / 10.0),
            "edge_intensity": min(1.0, total_edge_weight / 100.0),
            "evidence_diversity": min(1.0, len(evidence_types) / 5.0),
            "corridor_count": min(1.0, len(corridors) / 3.0),
        }
        
        threat_level = sum(threat_factors.values()) / len(threat_factors)
        
        entities_involved = [n.get("id", "") for n in nodes if n.get("id") != entity_id]
        
        return {
            "threat_level": threat_level,
            "attack_type": attack_type,
            "entities_involved": entities_involved,
            "evidence_count": len(all_evidence),
            "corridors": corridors,
            "threat_factors": threat_factors,
        }

    def _classify_attack(self, evidence_list: list) -> str:
        """Classify the attack type based on evidence patterns."""
        type_counts: Dict[str, int] = {}
        for ev in evidence_list:
            if isinstance(ev, dict):
                ev_type = ev.get("type", "unknown")
                type_counts[ev_type] = type_counts.get(ev_type, 0) + 1
        
        if not type_counts:
            return "unknown"
        
        # Map evidence types to attack categories
        attack_map = {
            "port_scan": "reconnaissance",
            "credential_access": "credential_theft",
            "lateral_movement": "lateral_movement",
            "data_transfer": "exfiltration",
            "phishing_link": "phishing",
            "login_attempt": "brute_force",
            "suspicious_process": "execution",
            "convergence_pattern": "coordinated_attack",
            "pivot_pattern": "lateral_movement",
            "timing_anomaly": "rapid_attack",
            "soldier_investigation": "confirmed_threat",
        }
        
        # Find most common evidence type and map to attack
        most_common = max(type_counts, key=type_counts.get)
        return attack_map.get(most_common, "unknown")

    def to_status(self) -> Dict[str, Any]:
        """Return serializable status."""
        return {
            "ant_id": self.ant_id,
            "ant_type": self.ant_type,
            "state": self.state,
            "current_entity": self.current_entity,
            "pheromones_deposited": self.pheromones_deposited,
            "anomalies_found": self.anomalies_found,
            "last_active": self.last_active,
            "investigations": len(self.investigation_history),
            "findings_count": len(self.findings),
        }


# ── Queen Agent ────────────────────────────────────────────────────────

class QueenAgent:
    """
    Singleton coordinator that runs global pattern recognition.
    
    Periodically:
    1. Reads the full pheromone graph
    2. Identifies high-pheromone clusters and attack corridors
    3. Issues directives to soldiers for investigation
    4. Triggers incident creation and SOAR responses
    """

    def __init__(self, analysis_interval: float = 15.0):
        self.ant_id = "queen-0"
        self.ant_type = "queen"
        self.state = "idle"
        self.analysis_interval = analysis_interval
        self.last_active = time.time()
        self.directives_issued = 0
        self.incidents_triggered = 0
        self.findings: List[Dict[str, Any]] = []
        self._running = False

    async def start(self, graph, coordinator: "SwarmCoordinator"):
        """Start the queen's analysis loop."""
        self._running = True
        self.state = "analyzing"
        logger.info("👑 Queen agent started global analysis")
        
        while self._running:
            try:
                await self._analysis_cycle(graph, coordinator)
                await asyncio.sleep(self.analysis_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queen error: {e}", exc_info=True)
                await asyncio.sleep(5.0)
        
        self.state = "idle"
        logger.info("👑 Queen agent stopped")

    async def _analysis_cycle(self, graph, coordinator: "SwarmCoordinator"):
        """Execute one analysis cycle."""
        self.last_active = time.time()
        
        # Step 1: Trigger pheromone decay
        pruned = graph.decay_all()
        if pruned > 0:
            logger.debug(f"👑 Queen: decayed graph, pruned {pruned} edges")
        
        # Step 2: Find hotspots
        hotspots = graph.get_hotspots(top_n=5)
        
        # Step 3: Find attack corridors
        corridors = graph.get_attack_corridors(min_strength=3.0)
        
        # Step 4: Issue directives for high-pheromone hotspots
        for hotspot in hotspots:
            entity_id = hotspot["entity_id"]
            total_ph = hotspot["total_pheromone"]
            
            if total_ph > coordinator.soldier_threshold:
                # Check if already being investigated
                if not coordinator.is_under_investigation(entity_id):
                    await coordinator.request_soldier(
                        entity_id,
                        f"Queen directive: hotspot with pheromone {total_ph:.1f}"
                    )
                    self.directives_issued += 1
        
        # Step 5: Detect attack corridors that need incident creation
        if len(corridors) >= 2:
            # Multiple high-strength corridors suggest coordinated attack
            corridor_entities = set()
            for c in corridors:
                corridor_entities.add(c["source"])
                corridor_entities.add(c["target"])
            
            finding = {
                "type": "corridor_cluster",
                "corridors": len(corridors),
                "entities": list(corridor_entities),
                "total_weight": sum(c["weight"] for c in corridors),
                "timestamp": time.time()
            }
            self.findings.append(finding)
            
            logger.warning(
                f"👑 Queen: detected {len(corridors)} attack corridors "
                f"involving {len(corridor_entities)} entities"
            )
        
        # Step 6: Broadcast graph snapshot for dashboard
        if coordinator.on_graph_update:
            snapshot = graph.to_snapshot()
            await coordinator.on_graph_update(snapshot)

    def stop(self):
        """Stop the queen's analysis loop."""
        self._running = False

    def to_status(self) -> Dict[str, Any]:
        return {
            "ant_id": self.ant_id,
            "ant_type": self.ant_type,
            "state": self.state,
            "last_active": self.last_active,
            "directives_issued": self.directives_issued,
            "incidents_triggered": self.incidents_triggered,
            "findings_count": len(self.findings),
        }


# ── Swarm Coordinator ─────────────────────────────────────────────────

class SwarmCoordinator:
    """
    Manages the lifecycle of all ant agents, the pheromone graph,
    and coordinates between scouts, soldiers, and the queen.
    """

    def __init__(
        self,
        num_scouts: int = 5,
        soldier_threshold: float = 15.0,
        scout_interval: float = 3.0,
        queen_interval: float = 15.0,
    ):
        self.num_scouts = num_scouts
        self.soldier_threshold = soldier_threshold
        self.scout_interval = scout_interval
        self.queen_interval = queen_interval
        
        self.scouts: List[ScoutAnt] = []
        self.soldiers: List[SoldierAnt] = []
        self.queen: Optional[QueenAgent] = None
        
        self.is_running = False
        self.start_time: Optional[float] = None
        self._tasks: List[asyncio.Task] = []
        self._entities_under_investigation: Set[str] = set()
        self._soldier_reports: List[Dict[str, Any]] = []
        
        # Metrics
        self.total_pheromones_deposited = 0
        self.total_incidents_created = 0
        
        # Callback for dashboard WebSocket broadcast
        self.on_graph_update = None
        self.on_incident = None
        self.on_ant_activity = None

    async def start(self, graph):
        """Start the full swarm: scouts, queen, and decay timer."""
        if self.is_running:
            logger.warning("Swarm already running")
            return
        
        self.is_running = True
        self.start_time = time.time()
        logger.info(f"🐝🐝🐝 Starting swarm with {self.num_scouts} scouts")
        
        # Create and start scouts
        for i in range(self.num_scouts):
            scout = ScoutAnt(
                ant_id=f"scout-{i:02d}",
                probe_interval=self.scout_interval
            )
            self.scouts.append(scout)
            task = asyncio.create_task(scout.start(graph, self))
            scout._task = task
            self._tasks.append(task)
        
        # Create and start queen
        self.queen = QueenAgent(analysis_interval=self.queen_interval)
        queen_task = asyncio.create_task(self.queen.start(graph, self))
        self._tasks.append(queen_task)
        
        logger.info(f"🐝🐝🐝 Swarm active: {len(self.scouts)} scouts, 1 queen")

    async def stop(self):
        """Stop all agents and clean up."""
        self.is_running = False
        
        # Stop all scouts
        for scout in self.scouts:
            scout.stop()
        
        # Stop queen
        if self.queen:
            self.queen.stop()
        
        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to finish
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        self._tasks.clear()
        logger.info("🐝🐝🐝 Swarm stopped")

    async def request_soldier(self, target_entity: str, reason: str):
        """Deploy a soldier ant to investigate a specific entity."""
        if target_entity in self._entities_under_investigation:
            return
        
        self._entities_under_investigation.add(target_entity)
        
        soldier = SoldierAnt()
        self.soldiers.append(soldier)
        
        logger.info(f"🐝 Deploying soldier {soldier.ant_id} to investigate {target_entity}")
        
        # Notify dashboard
        if self.on_ant_activity:
            await self.on_ant_activity({
                "event": "soldier_deployed",
                "ant_id": soldier.ant_id,
                "target": target_entity,
                "reason": reason,
                "timestamp": time.time()
            })
        
        # Run investigation in background
        from swarm_graph import pheromone_graph
        task = asyncio.create_task(
            self._run_soldier_investigation(soldier, target_entity, reason, pheromone_graph)
        )
        self._tasks.append(task)

    async def _run_soldier_investigation(self, soldier: SoldierAnt, target: str, reason: str, graph):
        """Run a soldier investigation and handle cleanup."""
        try:
            result = await soldier.investigate(target, reason, graph, self)
        except Exception as e:
            logger.error(f"Soldier {soldier.ant_id} investigation failed: {e}", exc_info=True)
        finally:
            self._entities_under_investigation.discard(target)

    async def soldier_report(self, finding: Dict[str, Any]):
        """Receive a report from a soldier ant."""
        self._soldier_reports.append(finding)
        
        # Notify dashboard
        if self.on_ant_activity:
            await self.on_ant_activity({
                "event": "soldier_finding",
                "finding": finding,
                "timestamp": time.time()
            })
        
        # If threat level is high enough, trigger incident creation via correlation
        if finding.get("threat_level", 0) > 0.5:
            logger.warning(
                f"🚨 High-threat finding from {finding['ant_id']}: "
                f"level={finding['threat_level']:.2f} at {finding['entity']}"
            )

    def is_under_investigation(self, entity_id: str) -> bool:
        """Check if an entity is currently being investigated by a soldier."""
        return entity_id in self._entities_under_investigation

    def get_status(self) -> Dict[str, Any]:
        """Get overall swarm status."""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        # Aggregate metrics from all ants
        total_ph = sum(s.pheromones_deposited for s in self.scouts) + \
                   sum(s.pheromones_deposited for s in self.soldiers)
        total_anomalies = sum(s.anomalies_found for s in self.scouts) + \
                         sum(s.anomalies_found for s in self.soldiers)
        
        return {
            "is_running": self.is_running,
            "uptime_seconds": uptime,
            "scout_count": len(self.scouts),
            "soldier_count": len(self.soldiers),
            "queen_active": self.queen is not None and self.queen.state != "idle",
            "active_investigations": len(self._entities_under_investigation),
            "total_pheromones_deposited": total_ph,
            "total_anomalies_found": total_anomalies,
            "total_soldier_reports": len(self._soldier_reports),
            "scouts": [s.to_status() for s in self.scouts],
            "soldiers": [s.to_status() for s in self.soldiers],
            "queen": self.queen.to_status() if self.queen else None,
        }

    def get_recent_activity(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent ant activity for the dashboard feed."""
        # Combine scout findings and soldier reports
        all_activity = []
        
        for scout in self.scouts:
            for finding in scout.findings[-5:]:  # Last 5 per scout
                all_activity.append({
                    "type": "scout_finding",
                    **finding
                })
        
        for report in self._soldier_reports[-10:]:
            all_activity.append({
                "type": "soldier_report",
                **report
            })
        
        # Sort by timestamp, most recent first
        all_activity.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return all_activity[:limit]


# ── Module-level singleton ─────────────────────────────────────────────

swarm_coordinator = SwarmCoordinator()
