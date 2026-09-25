import pytest
from incident import IncidentManager, IncidentStatus, IncidentSeverity, get_severity_from_score
from storage import clear_all_state

class DummyStorage:
    def __init__(self):
        self.incidents = {}
        self.next_id = 1
        
    def create_incident(self, data):
        data["id"] = self.next_id
        self.incidents[self.next_id] = data
        self.next_id += 1
        return data["id"]
        
    def get_incident(self, iid):
        return self.incidents.get(iid)
        
    def update_incident(self, iid, updates):
        if iid in self.incidents:
            self.incidents[iid].update(updates)
            return self.incidents[iid]
        return None
        
    def list_incidents(self):
        return list(self.incidents.values())

@pytest.fixture
def manager():
    return IncidentManager(storage_client=DummyStorage())

def test_get_severity_from_score():
    assert get_severity_from_score(85) == IncidentSeverity.CRITICAL
    assert get_severity_from_score(65) == IncidentSeverity.HIGH
    assert get_severity_from_score(45) == IncidentSeverity.MEDIUM
    assert get_severity_from_score(20) == IncidentSeverity.LOW

def test_create_incident(manager):
    data = {"score": 85.0, "entities": [{"type": "ip", "id": "1.1.1.1"}]}
    incident = manager.create_incident(data)
    assert incident["id"] == 1
    assert incident["status"] == "open"
    assert incident["severity"] == "critical"
    
def test_transition_status(manager):
    incident = manager.create_incident({"score": 50})
    iid = incident["id"]
    
    # open -> investigating
    res = manager.transition_status(iid, IncidentStatus.INVESTIGATING)
    assert res["status"] == "investigating"
    
    # investigating -> mitigated
    res = manager.transition_status(iid, IncidentStatus.MITIGATED)
    assert res["status"] == "mitigated"
    
    # Invalid transition (mitigated -> open) should return None
    res_invalid = manager.transition_status(iid, IncidentStatus.OPEN)
    assert res_invalid is None
    # Status should remain mitigated
    assert manager.get_incident(iid)["status"] == "mitigated"

def test_add_comment(manager):
    incident = manager.create_incident({"score": 50})
    iid = incident["id"]
    
    res = manager.add_comment(iid, "Looking into this", "analyst1")
    assert len(res["comments"]) == 1
    assert res["comments"][0]["text"] == "Looking into this"
    assert res["comments"][0]["author"] == "analyst1"

def test_add_tags(manager):
    incident = manager.create_incident({"score": 50})
    iid = incident["id"]
    
    res = manager.add_tags(iid, ["malware", "urgent"])
    assert "malware" in res["tags"]
    assert "urgent" in res["tags"]

def test_search(manager):
    manager.create_incident({"score": 90, "entities": [{"type": "ip", "id": "1.1.1.1"}], "mitre": ["T1566"]})
    manager.create_incident({"score": 40, "entities": [{"type": "user", "id": "alice"}], "mitre": ["T1021"]})
    
    # Search by score
    res = manager.search(min_score=80)
    assert len(res) == 1
    assert res[0]["score"] == 90
    
    # Search by entity type
    res = manager.search(entity_type="user")
    assert len(res) == 1
    assert res[0]["entities"][0]["id"] == "alice"
    
    # Search by mitre
    res = manager.search(mitre_technique="T1566")
    assert len(res) == 1

def test_group_incidents(manager):
    manager.create_incident({"score": 90, "severity": "critical"})
    manager.create_incident({"score": 85, "severity": "critical"})
    manager.create_incident({"score": 40, "severity": "medium"})
    
    groups = manager.group_incidents(group_by="severity")
    assert len(groups["critical"]) == 2
    assert len(groups["medium"]) == 1

def test_get_related_incidents(manager):
    manager.create_incident({"score": 90, "entities": [{"type": "ip", "id": "1.1.1.1"}], "mitre": ["T1566"]})
    manager.create_incident({"score": 80, "entities": [{"type": "ip", "id": "1.1.1.1"}], "mitre": ["T1589"]})
    manager.create_incident({"score": 40, "entities": [{"type": "user", "id": "alice"}], "mitre": ["T1021"]})
    
    # Incident 1 (ID=1) shares IP with Incident 2 (ID=2)
    related = manager.get_related_incidents(1, relatedness_threshold=0.5)
    assert len(related) == 1
    assert related[0]["incident"]["id"] == 2
    assert related[0]["relation"] == "shared_entity"

def test_batch_update_status(manager):
    i1 = manager.create_incident({"score": 50})
    i2 = manager.create_incident({"score": 60})
    
    res = manager.batch_update_status([i1["id"], i2["id"]], "investigating", "Bulk update", "system")
    assert res["success"] == 2
    assert res["failed"] == 0
    assert manager.get_incident(i1["id"])["status"] == "investigating"
    assert len(manager.get_incident(i2["id"])["comments"]) == 1

def test_get_statistics(manager):
    manager.create_incident({"score": 90, "status": "open", "mitre": ["T1566"]})
    manager.create_incident({"score": 40, "status": "investigating", "mitre": ["T1566"]})
    
    stats = manager.get_statistics()
    assert stats["total"] == 2
    assert stats["critical_count"] == 1
    assert stats["by_status"]["open"] == 1
    assert stats["by_status"]["investigating"] == 1
    assert stats["by_mitre"]["T1566"] == 2
    assert stats["avg_score"] == 65.0
