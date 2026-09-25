"""Correlation engine for swarm-based incident detection.

Aggregates pheromones within time windows, deduplicates evidence,
performs multi-entity correlation, and creates incidents when thresholds are met.
"""
from typing import List, Dict, Set, Tuple
import logging
import time
from api.logging_utils import logfmt
from storage import get_pheromones_snapshot, create_incident, list_incidents

logger = logging.getLogger("honeypot.correlation")

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes

MITRE_KEYWORDS = {
    "T1556": ["credential", "login", "auth", "password", "session"],
    "T1021": ["lateral", "pivot", "rdp", "ssh", "psexec", "admin"],
    "T1566": ["phish", "link", "url", "email", "attachment"],
    "T1548": ["payment", "upi", "bank", "account", "transfer"],
    "T1588": ["malware", "tool", "payload", "shellcode"],
    "T1589": ["scan", "recon", "enumerate", "fingerprint", "probe"],
    "T1591": ["identity", "name", "email", "phone", "address"],
    "T1592": ["device", "os", "browser", "software", "version"],
    "T1598": ["social", "trick", "deceive", "spoof", "impersonate"],
}

PREDICTED_NEXT_STEPS = {
    "T1556": ["revoke_session", "reset_credentials"],
    "T1021": ["isolate_host", "snapshot"],
    "T1566": ["block_ip", "snapshot"],
    "T1548": ["snapshot", "disable_user"],
}

# ── Kill Chain State Machine (Innovation) ─────────────────────────────
# MITRE ATT&CK Enterprise kill chain stages in order.
# When an incident progresses through multiple stages, the risk
# escalates non-linearly — proving intent, not just noise.

KILL_CHAIN_STAGES = [
    {"stage": "reconnaissance", "techniques": ["T1589", "T1591", "T1592"], "base_score": 20},
    {"stage": "initial_access", "techniques": ["T1566", "T1598"], "base_score": 40},
    {"stage": "execution", "techniques": ["T1588"], "base_score": 55},
    {"stage": "credential_access", "techniques": ["T1556"], "base_score": 70},
    {"stage": "lateral_movement", "techniques": ["T1021"], "base_score": 80},
    {"stage": "collection", "techniques": ["T1548"], "base_score": 85},
    {"stage": "exfiltration", "techniques": [], "base_score": 95},
]

TECHNIQUE_DESCRIPTIONS = {
    "T1556": "Credential Access — Modify Authentication Process",
    "T1021": "Lateral Movement — Remote Services",
    "T1566": "Initial Access — Phishing",
    "T1548": "Privilege Escalation — Abuse Elevation Control",
    "T1588": "Resource Development — Obtain Capabilities",
    "T1589": "Reconnaissance — Gather Victim Identity",
    "T1591": "Reconnaissance — Gather Victim Org Information",
    "T1592": "Reconnaissance — Gather Victim Host Information",
    "T1598": "Reconnaissance — Phishing for Information",
}

# Active kill chain tracking: entity_key → list of stages observed
_kill_chain_state: Dict[str, List[str]] = {}


def get_kill_chain_stage(mitre_techniques: List[str]) -> List[str]:
    """Map MITRE techniques to kill chain stages."""
    stages = []
    for stage_info in KILL_CHAIN_STAGES:
        if any(t in mitre_techniques for t in stage_info["techniques"]):
            stages.append(stage_info["stage"])
    return stages


def update_kill_chain(entity_key: str, mitre_techniques: List[str]) -> Dict:
    """Track kill chain progression for an entity.

    Returns a dict with:
    - stages_reached: list of kill chain stages observed
    - progression: how far through the kill chain (0-100%)
    - escalation_multiplier: score multiplier based on chain length
    """
    stages = get_kill_chain_stage(mitre_techniques)
    existing = _kill_chain_state.get(entity_key, [])

    for stage in stages:
        if stage not in existing:
            existing.append(stage)

    _kill_chain_state[entity_key] = existing

    total_stages = len(KILL_CHAIN_STAGES)
    progression = len(existing) / total_stages * 100 if total_stages > 0 else 0

    # Non-linear escalation: each additional stage multiplies risk
    # 1 stage = 1.0x, 2 stages = 1.3x, 3 stages = 1.7x, 4+ = 2.0x+
    if len(existing) <= 1:
        multiplier = 1.0
    elif len(existing) == 2:
        multiplier = 1.3
    elif len(existing) == 3:
        multiplier = 1.7
    else:
        multiplier = 2.0 + (len(existing) - 4) * 0.3

    return {
        "stages_reached": existing,
        "progression": round(progression, 1),
        "escalation_multiplier": round(multiplier, 2),
        "stage_count": len(existing),
    }


def _map_evidence_to_mitre(evidence_list: List[Dict]) -> List[str]:
    techniques = set()
    for e in evidence_list:
        text = " ".join(str(v).lower() for v in e.values() if v)
        for technique, keywords in MITRE_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                techniques.add(technique)
    return sorted(list(techniques))


def _deduplicate_evidence(evidence_list: List) -> List[Dict]:
    seen = set()
    deduped = []
    flattened = []
    for e in evidence_list:
        if isinstance(e, dict):
            flattened.append(e)
        elif isinstance(e, list):
            flattened.extend(e)

    for e in flattened:
        if not isinstance(e, dict):
            continue
        key = (e.get("type"), e.get("text"), e.get("source"))
        if key not in seen:
            seen.add(key)
            deduped.append(e)
    return deduped


def _correlate_entities(pheromones_list: List[Dict], window_seconds: float) -> List[Tuple[Set[str], List[Dict]]]:
    clusters = []
    processed_indices = set()

    for i, p1 in enumerate(pheromones_list):
        if i in processed_indices:
            continue

        ts1 = p1.get("ts", time.time())
        evidence1 = p1.get("evidence", [])
        if isinstance(evidence1, dict):
            evidence_types1 = {evidence1.get("type")} if "type" in evidence1 else set()
        elif isinstance(evidence1, list):
            evidence_types1 = {e.get("type") for e in evidence1 if isinstance(e, dict)}
        else:
            evidence_types1 = set()

        cluster_indices = {i}
        for j, p2 in enumerate(pheromones_list[i + 1 :], start=i + 1):
            if j in processed_indices:
                continue

            ts2 = p2.get("ts", time.time())
            evidence2 = p2.get("evidence", [])
            if isinstance(evidence2, dict):
                evidence_types2 = {evidence2.get("type")} if "type" in evidence2 else set()
            elif isinstance(evidence2, list):
                evidence_types2 = {e.get("type") for e in evidence2 if isinstance(e, dict)}
            else:
                evidence_types2 = set()

            if abs(ts1 - ts2) <= window_seconds and evidence_types1 and evidence_types2 and (evidence_types1 & evidence_types2):
                cluster_indices.add(j)

        if cluster_indices:
            cluster_pheromones = [pheromones_list[idx] for idx in cluster_indices]
            entity_set = {f"{p['entity_type']}:{p['entity_id']}" for p in cluster_pheromones}
            clusters.append((entity_set, cluster_pheromones))
            processed_indices.update(cluster_indices)

    return clusters


def _incident_signature(incident: Dict) -> Tuple:
    entities = tuple(sorted((entity.get("type"), entity.get("id")) for entity in incident.get("entities", [])))
    evidence = tuple(
        sorted((item.get("type"), item.get("text"), item.get("source")) for item in incident.get("evidence", []))
    )
    mitre = tuple(sorted(incident.get("mitre", [])))
    return incident.get("correlation_type"), entities, evidence, mitre


def _existing_signatures(window_seconds: float) -> Set[Tuple]:
    now = time.time()
    signatures = set()
    for incident in list_incidents():
        created_at = float(incident.get("created_at", incident.get("last_action_at", now)))
        if now - created_at <= window_seconds:
            signatures.add(_incident_signature(incident))
    return signatures


def _predict_next_steps(mitre: List[str]) -> List[str]:
    steps = []
    for technique in mitre:
        steps.extend(PREDICTED_NEXT_STEPS.get(technique, []))
    deduped = []
    for step in steps:
        if step not in deduped:
            deduped.append(step)
    return deduped


def _create_incident_if_new(incident: Dict, created: List[Dict], signatures: Set[Tuple]) -> None:
    signature = _incident_signature(incident)
    if signature in signatures:
        return

    incident["created_at"] = time.time()
    incident["predicted_next_steps"] = _predict_next_steps(incident.get("mitre", []))
    incident_id = create_incident(incident)
    incident["id"] = incident_id
    signatures.add(signature)
    created.append(incident)


def evaluate_correlation(create_threshold: float = 60.0, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> List[Dict]:
    created = []
    pheromones = get_pheromones_snapshot()
    if not pheromones:
        return created

    existing_signatures = _existing_signatures(window_seconds)
    clusters = _correlate_entities(pheromones, window_seconds)
    correlated_entity_keys = set()

    if clusters:
        for entity_set, cluster_pheromones in clusters:
            if len(cluster_pheromones) <= 1:
                continue

            aggregated_score = sum(float(p.get("score", 0)) for p in cluster_pheromones) / len(cluster_pheromones)
            all_evidence = []
            for pheromone in cluster_pheromones:
                all_evidence.extend(pheromone.get("evidence", []))

            deduped_evidence = _deduplicate_evidence(all_evidence)
            mitre = _map_evidence_to_mitre(deduped_evidence)
            if aggregated_score < create_threshold:
                continue

            correlated_entity_keys.update(entity_set)
            incident = {
                "entities": [{"type": ent.split(":")[0], "id": ent.split(":", 1)[1]} for ent in sorted(entity_set)],
                "score": aggregated_score,
                "evidence": deduped_evidence,
                "mitre": mitre,
                "status": "open",
                "correlation_type": "multi_entity",
            }
            _create_incident_if_new(incident, created, existing_signatures)
            if incident.get("id"):
                logger.info(logfmt(
                    "incident_created",
                    id=incident["id"],
                    score=aggregated_score,
                    type="multi_entity",
                    entities=len(entity_set),
                    evidence=len(deduped_evidence)
                ))

        seen_entities = set()
        for pheromone in pheromones:
            entity_key = f"{pheromone['entity_type']}:{pheromone['entity_id']}"
            if entity_key in seen_entities or entity_key in correlated_entity_keys:
                continue
            seen_entities.add(entity_key)

            score = float(pheromone.get("score", 0))
            if score < create_threshold:
                continue

            evidence = _deduplicate_evidence(pheromone.get("evidence", []))
            mitre = _map_evidence_to_mitre(evidence)
            incident = {
                "entities": [{"type": pheromone["entity_type"], "id": pheromone["entity_id"]}],
                "score": score,
                "evidence": evidence,
                "mitre": mitre,
                "status": "open",
                "correlation_type": "single_entity",
            }
            _create_incident_if_new(incident, created, existing_signatures)
            if incident.get("id"):
                logger.info(logfmt(
                    "incident_created",
                    id=incident["id"],
                    score=score,
                    type="single_entity",
                    entity=entity_key
                ))
    else:
        for pheromone in pheromones:
            score = float(pheromone.get("score", 0))
            if score < create_threshold:
                continue

            evidence = _deduplicate_evidence(pheromone.get("evidence", []))
            mitre = _map_evidence_to_mitre(evidence)
            incident = {
                "entities": [{"type": pheromone["entity_type"], "id": pheromone["entity_id"]}],
                "score": score,
                "evidence": evidence,
                "mitre": mitre,
                "status": "open",
                "correlation_type": "single_entity",
            }
            _create_incident_if_new(incident, created, existing_signatures)
            if incident.get("id"):
                logger.info(logfmt(
                    "incident_created",
                    id=incident["id"],
                    score=score,
                    type="single_entity",
                    entity=pheromone["entity_id"]
                ))

    return created

def reset_correlation_state() -> None:
    """Clear internal state, primarily for testing purposes."""
    _kill_chain_state.clear()
    logger.info(logfmt("correlation_state_reset"))
