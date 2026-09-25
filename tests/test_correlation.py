import pytest
import time
from correlation import (
    get_kill_chain_stage,
    update_kill_chain,
    _map_evidence_to_mitre,
    _deduplicate_evidence,
    evaluate_correlation,
    reset_correlation_state,
    KILL_CHAIN_STAGES
)
from storage import add_pheromone, clear_all_state, list_incidents

@pytest.fixture(autouse=True)
def setup_and_teardown():
    clear_all_state()
    reset_correlation_state()
    yield
    clear_all_state()
    reset_correlation_state()

def test_get_kill_chain_stage():
    # T1589 is reconnaissance
    assert "reconnaissance" in get_kill_chain_stage(["T1589"])
    # T1556 is credential_access
    assert "credential_access" in get_kill_chain_stage(["T1556"])
    # Both
    stages = get_kill_chain_stage(["T1589", "T1556"])
    assert "reconnaissance" in stages
    assert "credential_access" in stages

def test_update_kill_chain():
    # Initial state
    result1 = update_kill_chain("ip:1.1.1.1", ["T1589"])
    assert "reconnaissance" in result1["stages_reached"]
    assert result1["stage_count"] == 1
    assert result1["escalation_multiplier"] == 1.0

    # Progress to next stage
    result2 = update_kill_chain("ip:1.1.1.1", ["T1556"])
    assert "reconnaissance" in result2["stages_reached"]
    assert "credential_access" in result2["stages_reached"]
    assert result2["stage_count"] == 2
    assert result2["escalation_multiplier"] == 1.3

    # Progress to 4 stages
    update_kill_chain("ip:1.1.1.1", ["T1566"]) # initial_access
    result4 = update_kill_chain("ip:1.1.1.1", ["T1021"]) # lateral_movement
    assert result4["stage_count"] == 4
    assert result4["escalation_multiplier"] == 2.0

def test_map_evidence_to_mitre():
    evidence = [{"type": "syslog", "text": "failed login attempt on ssh", "source": "auth.log"}]
    techniques = _map_evidence_to_mitre(evidence)
    # 'login' should map to T1556, 'ssh' to T1021
    assert "T1556" in techniques
    assert "T1021" in techniques

def test_deduplicate_evidence():
    evidence = [
        {"type": "syslog", "text": "failed login", "source": "auth.log"},
        {"type": "syslog", "text": "failed login", "source": "auth.log"}, # Duplicate
        {"type": "syslog", "text": "success login", "source": "auth.log"}
    ]
    deduped = _deduplicate_evidence(evidence)
    assert len(deduped) == 2

def test_evaluate_correlation_single_entity():
    # Add pheromone for a single entity above threshold
    add_pheromone(
        entity_type="ip", 
        entity_id="1.2.3.4", 
        score=75.0, 
        evidence={"type": "log", "text": "failed login auth"}
    )
    
    incidents = evaluate_correlation(create_threshold=60.0, window_seconds=300)
    assert len(incidents) == 1
    assert incidents[0]["correlation_type"] == "single_entity"
    assert incidents[0]["score"] == 75.0
    assert "T1556" in incidents[0]["mitre"]
    
    # Check that incident was saved
    saved = list_incidents()
    assert len(saved) == 1
    assert saved[0]["correlation_type"] == "single_entity"

def test_evaluate_correlation_multi_entity():
    # Add pheromones for two entities with same evidence type in time window
    ts = time.time()
    add_pheromone(
        entity_type="ip", 
        entity_id="10.0.0.1", 
        score=80.0, 
        evidence={"type": "lateral", "text": "psexec execution"},
        ts=ts
    )
    add_pheromone(
        entity_type="host", 
        entity_id="srv-01", 
        score=70.0, 
        evidence={"type": "lateral", "text": "psexec execution"},
        ts=ts + 10
    )
    
    incidents = evaluate_correlation(create_threshold=60.0, window_seconds=300)
    assert len(incidents) == 1
    assert incidents[0]["correlation_type"] == "multi_entity"
    # Average score = 75
    assert incidents[0]["score"] == 75.0
    assert len(incidents[0]["entities"]) == 2
    assert incidents[0]["entities"][0]["id"] == "10.0.0.1" or incidents[0]["entities"][1]["id"] == "10.0.0.1"

def test_evaluate_correlation_deduplication_window():
    # Test that existing signatures within window are not recreated
    add_pheromone(
        entity_type="ip", 
        entity_id="9.9.9.9", 
        score=90.0, 
        evidence={"type": "test", "text": "malware payload"}
    )
    
    # First run creates the incident
    incidents1 = evaluate_correlation(create_threshold=60.0, window_seconds=300)
    assert len(incidents1) == 1
    
    # Second run immediately after shouldn't create a new one for the same signature
    incidents2 = evaluate_correlation(create_threshold=60.0, window_seconds=300)
    assert len(incidents2) == 0
