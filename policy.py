"""Policy engine for simulated containment actions driven by playbook manifests."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from schemas import PlaybookManifest
from storage import add_audit_log, get_incident, update_incident

logger = logging.getLogger("honeypot.policy")

PLAYBOOKS_DIR = Path(__file__).resolve().parent / "playbooks"
SEVERITY_WEIGHTS = {
    "low": 1.0,
    "medium": 1.5,
    "high": 2.0,
    "critical": 2.5,
}
PARAM_TYPE_CHECKS = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


def load_playbooks() -> List[Dict[str, Any]]:
    manifests: List[Dict[str, Any]] = []
    if not PLAYBOOKS_DIR.exists():
        return manifests

    for path in sorted(PLAYBOOKS_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        manifests.append(PlaybookManifest(**raw).model_dump())
    return manifests


def _find_action_definition(action: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    for manifest in load_playbooks():
        for action_def in manifest.get("actions", []):
            if action_def.get("action") == action:
                return manifest, action_def
    raise ValueError(f"unknown action '{action}'")


def _validate_params(action_def: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    params = params or {}
    validated: Dict[str, Any] = {}
    expected_specs = action_def.get("params", [])
    expected_names = {spec["name"] for spec in expected_specs}

    unexpected = sorted(set(params) - expected_names)
    if unexpected:
        raise ValueError(f"unexpected params for action '{action_def['action']}': {', '.join(unexpected)}")

    for spec in expected_specs:
        name = spec["name"]
        required = spec.get("required", False)
        if name not in params:
            if required and "default" not in spec:
                raise ValueError(f"missing required param '{name}'")
            if "default" in spec:
                validated[name] = spec.get("default")
            continue

        value = params[name]
        expected_type = spec["type"]
        checker = PARAM_TYPE_CHECKS[expected_type]
        if expected_type == "integer" and isinstance(value, bool):
            raise ValueError(f"param '{name}' must be integer")
        if expected_type == "number" and isinstance(value, bool):
            raise ValueError(f"param '{name}' must be number")
        if not isinstance(value, checker):
            raise ValueError(f"param '{name}' must be {expected_type}")
        validated[name] = value

    return validated


def _calculate_blast_radius(incident: Dict[str, Any], action_def: Dict[str, Any], params: Dict[str, Any]) -> float:
    severity_weight = SEVERITY_WEIGHTS.get(incident.get("severity", "medium"), 1.5)
    entity_count = max(1, len(incident.get("entities", [])))
    score_component = float(incident.get("score", 0)) * 0.45
    entity_component = entity_count * 8.0
    param_component = max(0, len(params) - 1) * 4.0
    raw_radius = (score_component + entity_component + param_component) * float(
        action_def.get("blast_radius_multiplier", 1.0)
    ) * severity_weight / 1.5
    return round(min(100.0, raw_radius), 2)


def _should_escalate(incident: Dict[str, Any], action_def: Dict[str, Any], blast_radius: float) -> bool:
    return any(
        [
            blast_radius >= float(action_def.get("escalation_threshold", 70.0)),
            incident.get("severity") == "critical",
            len(incident.get("entities", [])) >= 3,
        ]
    )


def apply_action(incident_id: int, action: str, actor: str = "system", params: dict | None = None) -> dict:
    """Simulate playbook action execution against an incident with typed params."""
    incident = get_incident(incident_id)
    if not incident:
        raise ValueError("incident not found")

    manifest, action_def = _find_action_definition(action)
    validated_params = _validate_params(action_def, params or {})
    ts = time.time()
    blast_radius = _calculate_blast_radius(incident, action_def, validated_params)
    escalation_required = _should_escalate(incident, action_def, blast_radius)

    result = "escalation_required" if escalation_required else "simulated_success"
    incident_updates: Dict[str, Any] = {
        "last_action": action,
        "last_action_at": ts,
        "last_action_by": actor,
        "blast_radius": blast_radius,
    }
    if escalation_required:
        incident_updates["status"] = "investigating"
    elif action_def.get("resolves_incident"):
        incident_updates["status"] = action_def.get("status_on_success", "mitigated")
        incident_updates["mitigated_by"] = actor
        incident_updates["mitigated_at"] = ts

    updated_incident = update_incident(incident_id, incident_updates)
    entry = {
        "ts": ts,
        "actor": actor,
        "action": action,
        "params": validated_params,
        "playbook_id": manifest["playbook_id"],
        "simulation_only": bool(action_def.get("simulation_only", True)),
        "blast_radius": blast_radius,
        "escalation_required": escalation_required,
        "result": result,
    }
    add_audit_log(incident_id, entry)
    logger.info(
        "action_applied incident=%s action=%s actor=%s result=%s blast_radius=%.2f",
        incident_id,
        action,
        actor,
        result,
        blast_radius,
    )

    return {
        "incident_id": incident_id,
        "action": action,
        "status": "ok",
        "result": result,
        "playbook_id": manifest["playbook_id"],
        "blast_radius": blast_radius,
        "escalation_required": escalation_required,
        "validated_params": validated_params,
        "incident": updated_incident,
        "entry": entry,
    }
