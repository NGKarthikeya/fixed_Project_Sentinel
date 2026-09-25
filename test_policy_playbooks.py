import json

import policy
import storage


def setup_function():
    storage.reset_runtime_state()
    storage._redis_available = lambda: False


def test_apply_action_records_audit_and_updates_incident():
    incident_id = storage.create_incident(
        {
            "entities": [{"type": "ip", "id": "10.20.1.15"}],
            "score": 72.0,
            "severity": "high",
            "status": "open",
            "evidence": [],
            "mitre": ["T1566"],
        }
    )

    result = policy.apply_action(
        incident_id,
        "block_ip",
        actor="pytest",
        params={"target_ip": "10.20.1.15", "duration_minutes": 45},
    )

    assert result["result"] == "simulated_success"
    assert result["validated_params"]["target_ip"] == "10.20.1.15"
    assert storage.get_incident(incident_id)["status"] == "mitigated"
    audit = storage.get_audit_log(incident_id)
    assert len(audit) == 1
    assert audit[0]["action"] == "block_ip"
    assert audit[0]["playbook_id"] == "containment.core"


def test_apply_action_requires_escalation_for_high_blast_radius():
    incident_id = storage.create_incident(
        {
            "entities": [
                {"type": "host", "id": "host-1"},
                {"type": "user", "id": "alice"},
                {"type": "domain", "id": "bad.example"},
            ],
            "score": 88.0,
            "severity": "critical",
            "status": "open",
            "evidence": [],
            "mitre": ["T1021"],
        }
    )

    result = policy.apply_action(
        incident_id,
        "isolate_host",
        actor="pytest",
        params={"host_id": "host-1"},
    )

    assert result["escalation_required"] is True
    assert result["result"] == "escalation_required"
    assert storage.get_incident(incident_id)["status"] == "investigating"


def test_load_playbooks_has_typed_actions():
    playbooks = policy.load_playbooks()
    serialized = json.dumps(playbooks)
    assert "containment.core" in serialized
    assert "identity.response" in serialized
