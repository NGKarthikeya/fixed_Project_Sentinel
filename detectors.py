"""
Detector interface and implementations for swarm-style anomaly detection.

Detectors analyze telemetry signals and produce scores/signals that feed into pheromones.
"""
import math
from typing import Dict, Any, List
from collections import defaultdict
import logging

logger = logging.getLogger("detectors")

# In-memory storage for detector state (for demo; in production use Redis)
_detector_state = defaultdict(lambda: {"values": [], "entities": set(), "seen": 0})


class Detector:
    """Base detector interface."""
    
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a telemetry event and return signals.
        
        Args:
            event: Telemetry event dict with entity_type, entity_id, score, evidence, ts
        
        Returns:
            Dict with keys:
                - 'signal_type': str identifying this detector
                - 'score_delta': float (0-100) additional score contribution
                - 'reason': str explaining the signal
        """
        raise NotImplementedError


class ZScoreDetector(Detector):
    """
    Detects numeric feature drift using z-score.
    
    Compares the incoming score against historical mean/stddev for that entity.
    If score is > 2 std deviations above mean, signal anomaly.
    """
    
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        entity_key = f"{event['entity_type']}:{event['entity_id']}"
        state = _detector_state[entity_key]
        incoming_score = event.get("score", 10)
        
        # Need at least 3 samples to compute meaningful z-score
        if len(state["values"]) < 3:
            state["values"].append(incoming_score)
            state["seen"] += 1
            return {
                "signal_type": "zscore",
                "score_delta": 0,
                "reason": f"Insufficient history ({len(state['values'])}/3 samples)"
            }
        
        # Compute z-score using history (NOT including current event)
        history = state["values"]
        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        stddev = math.sqrt(variance) if variance > 0 else 0.1
        
        if stddev == 0:
            z_score = 0
        else:
            z_score = (incoming_score - mean) / stddev
        
        # Append to history after computing z-score
        state["values"].append(incoming_score)
        state["seen"] += 1
        
        # Anomaly if z-score > 2 (2 std deviations above mean)
        if z_score > 2:
            delta = min(50, z_score * 10)  # Scale z-score to 0-50 range
            logger.info(f"✓ ZScore anomaly: {entity_key} z={z_score:.2f} delta={delta:.1f}")
            return {
                "signal_type": "zscore",
                "score_delta": delta,
                "reason": f"Score z={z_score:.2f} (>{2} std deviations above mean {mean:.1f})"
            }
        
        return {
            "signal_type": "zscore",
            "score_delta": 0,
            "reason": f"Score z={z_score:.2f} within normal range"
        }


class FrequencyDetector(Detector):
    """
    Detects repeated suspicious tokens/entities across events.
    
    If the same entity appears repeatedly (e.g., same IP with UPI in evidence),
    signal accumulation/persistence.
    """
    
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        entity_key = f"{event['entity_type']}:{event['entity_id']}"
        state = _detector_state[entity_key]
        
        # Extract evidence tokens (simplified: count evidence items)
        evidence = event.get("evidence", [])
        evidence_count = len(evidence)
        
        state["entities"].add(entity_key)
        state["seen"] += 1
        
        # Signal if we've seen this entity multiple times with evidence
        times_seen = state["seen"]
        if times_seen >= 2 and evidence_count > 0:
            delta = min(30, times_seen * 5 + evidence_count * 5)
            logger.info(f"✓ Frequency anomaly: {entity_key} seen={times_seen} evidence={evidence_count} delta={delta:.1f}")
            return {
                "signal_type": "frequency",
                "score_delta": delta,
                "reason": f"Entity seen {times_seen} times with {evidence_count} evidence items (persistence pattern)"
            }
        
        return {
            "signal_type": "frequency",
            "score_delta": 0,
            "reason": f"Entity first or second appearance; no persistence signal yet"
        }


class SequenceDetector(Detector):
    """
    Detects anomalous sequences (patterns) in entity behavior.
    
    For example: if we see the same IP exhibit > 5 different scam types in sequence,
    or if we see rapid escalation from INITIAL to PAYMENT phase, signal anomaly.
    """
    
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        entity_key = f"{event['entity_type']}:{event['entity_id']}"
        state = _detector_state[entity_key]
        
        # Extract a "sequence context" from evidence (simplified: use evidence count as proxy for behavior richness)
        evidence = event.get("evidence", [])
        evidence_types = [e.get("type") if isinstance(e, dict) else "unknown" for e in evidence]
        
        # Track unique evidence types seen
        seen_types = set(evidence_types)
        if "unique_types" not in state:
            state["unique_types"] = set()
        state["unique_types"].update(seen_types)
        
        unique_count = len(state["unique_types"])
        
        # Signal if we see > 3 unique evidence types (suggests multi-faceted attack)
        if unique_count > 3:
            delta = min(40, unique_count * 8)
            logger.info(f"✓ Sequence anomaly: {entity_key} unique_types={unique_count} delta={delta:.1f}")
            return {
                "signal_type": "sequence",
                "score_delta": delta,
                "reason": f"Multi-faceted behavior: {unique_count} unique evidence types observed (coordinated attack)"
            }
        
        return {
            "signal_type": "sequence",
            "score_delta": 0,
            "reason": f"Sequence pattern simple ({unique_count} unique types); no anomaly"
        }


# Detector registry
DETECTORS = [
    ZScoreDetector(),
    FrequencyDetector(),
    SequenceDetector(),
]


def run_detectors(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all detectors on an event and aggregate signals.
    
    Returns:
        Dict with:
            - 'total_delta': float (sum of all detector score deltas)
            - 'signals': list of individual detector signals
    """
    signals = []
    total_delta = 0
    
    for detector in DETECTORS:
        try:
            signal = detector.detect(event)
            signals.append(signal)
            total_delta += signal.get("score_delta", 0)
        except Exception as e:
            logger.error(f"Detector {detector.__class__.__name__} failed: {e}", exc_info=True)
    
    return {
        "total_delta": min(100, total_delta),  # Cap at 100
        "signals": signals
    }


def reset_detector_state():
    """Reset in-memory detector state (for testing)."""
    global _detector_state
    _detector_state.clear()


# Alias used by the /swarm/reset endpoint
reset_detectors = reset_detector_state

