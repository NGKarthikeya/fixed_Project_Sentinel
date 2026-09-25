"""Incident management module with lifecycle, search, grouping, and batch operations."""

from typing import List, Dict, Optional, Set
from enum import Enum
import logging
import time
from collections import defaultdict

logger = logging.getLogger("honeypot.incident")


class IncidentStatus(str, Enum):
    """Incident lifecycle states."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, Enum):
    """Incident severity levels."""
    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # Urgent review needed
    MEDIUM = "medium"  # Review recommended
    LOW = "low"  # Monitor


def get_severity_from_score(score: float) -> IncidentSeverity:
    """Map incident score to severity."""
    if score >= 80:
        return IncidentSeverity.CRITICAL
    elif score >= 60:
        return IncidentSeverity.HIGH
    elif score >= 40:
        return IncidentSeverity.MEDIUM
    else:
        return IncidentSeverity.LOW


class IncidentManager:
    """Centralized incident lifecycle and enrichment manager."""
    
    def __init__(self, storage_client):
        """Initialize with storage client for persistence."""
        self.storage = storage_client
    
    def create_incident(self, incident_data: Dict) -> Dict:
        """Create and enrich incident with defaults."""
        now = time.time()
        
        # Enrich with defaults
        incident = {
            **incident_data,
            "id": None,  # Will be set by storage
            "created_at": now,
            "updated_at": now,
            "status": incident_data.get("status", IncidentStatus.OPEN.value),
            "severity": incident_data.get("severity") or get_severity_from_score(
                incident_data.get("score", 0)
            ).value,
            "comments": [],
            "tags": incident_data.get("tags", []),
        }
        
        # Store and return with ID
        incident_id = self.storage.create_incident(incident)
        incident["id"] = incident_id
        logger.info(f"incident_created id={incident_id} score={incident['score']:.1f} severity={incident['severity']}")
        return incident
    
    def get_incident(self, incident_id: int) -> Optional[Dict]:
        """Retrieve incident by ID."""
        return self.storage.get_incident(incident_id)
    
    def update_incident(self, incident_id: int, updates: Dict) -> Optional[Dict]:
        """Update incident and track changes."""
        incident = self.storage.get_incident(incident_id)
        if not incident:
            return None
        
        # Track lifecycle transition
        old_status = incident.get("status")
        new_status = updates.get("status")
        
        updates["updated_at"] = time.time()
        
        result = self.storage.update_incident(incident_id, updates)
        
        if old_status and new_status and old_status != new_status:
            logger.info(f"incident_status_changed id={incident_id} {old_status}->{new_status}")
        
        return result
    
    def transition_status(self, incident_id: int, new_status: IncidentStatus) -> Optional[Dict]:
        """Move incident to a new lifecycle state."""
        incident = self.storage.get_incident(incident_id)
        if not incident:
            return None
        
        current_status = IncidentStatus(incident.get("status", IncidentStatus.OPEN.value))
        
        # Validate transitions
        valid_transitions = {
            IncidentStatus.OPEN: [IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE],
            IncidentStatus.INVESTIGATING: [IncidentStatus.MITIGATED, IncidentStatus.FALSE_POSITIVE],
            IncidentStatus.MITIGATED: [IncidentStatus.RESOLVED],
            IncidentStatus.RESOLVED: [IncidentStatus.CLOSED],
            IncidentStatus.FALSE_POSITIVE: [IncidentStatus.CLOSED],
            IncidentStatus.CLOSED: [IncidentStatus.OPEN],  # Reopen if needed
        }
        
        if new_status not in valid_transitions.get(current_status, []):
            logger.warning(f"invalid_transition id={incident_id} {current_status.value}->{new_status.value}")
            return None
        
        return self.update_incident(incident_id, {"status": new_status.value})
    
    def add_comment(self, incident_id: int, comment: str, author: str = "system") -> Optional[Dict]:
        """Add a comment to an incident."""
        incident = self.storage.get_incident(incident_id)
        if not incident:
            return None
        
        entry = {
            "ts": time.time(),
            "author": author,
            "text": comment
        }
        
        comments = incident.get("comments", [])
        comments.append(entry)
        
        return self.storage.update_incident(incident_id, {"comments": comments})
    
    def add_tags(self, incident_id: int, tags: List[str]) -> Optional[Dict]:
        """Add tags to incident."""
        incident = self.storage.get_incident(incident_id)
        if not incident:
            return None
        
        current_tags = set(incident.get("tags", []))
        current_tags.update(tags)
        
        return self.storage.update_incident(incident_id, {"tags": list(current_tags)})
    
    def search(
        self,
        status: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        min_score: float = 0,
        max_score: float = 100,
        tags: Optional[List[str]] = None,
        created_after: Optional[float] = None,
        created_before: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Search incidents with multiple filter criteria."""
        all_incidents = self.storage.list_incidents()
        results = []
        
        for incident in all_incidents:
            # Status filter
            if status and incident.get("status") not in status:
                continue
            
            # Severity filter
            if severity and incident.get("severity") not in severity:
                continue
            
            # Score range filter
            score = incident.get("score", 0)
            if not (min_score <= score <= max_score):
                continue
            
            # Entity filters
            if entity_type or entity_id:
                entities = incident.get("entities", [])
                entity_match = False
                for ent in entities:
                    if entity_type and ent.get("type") != entity_type:
                        continue
                    if entity_id and ent.get("id") != entity_id:
                        continue
                    entity_match = True
                    break
                if not entity_match:
                    continue
            
            # MITRE technique filter
            if mitre_technique:
                mitre = incident.get("mitre", [])
                if mitre_technique not in mitre:
                    continue
            
            # Tags filter (must have all)
            if tags:
                incident_tags = set(incident.get("tags", []))
                if not set(tags).issubset(incident_tags):
                    continue
            
            # Time range filter
            created_at = incident.get("created_at", 0)
            if created_after and created_at < created_after:
                continue
            if created_before and created_at > created_before:
                continue
            
            results.append(incident)
        
        # Sort by score (descending) and return limited results
        results.sort(key=lambda x: (-x.get("score", 0), -x.get("created_at", 0)))
        return results[:limit]
    
    def group_incidents(
        self,
        group_by: str = "entity_type",
        filter_status: Optional[List[str]] = None,
        filter_severity: Optional[List[str]] = None,
    ) -> Dict[str, List[Dict]]:
        """Group incidents by a field (entity_type, entity_id, mitre_technique, severity)."""
        incidents = self.storage.list_incidents()
        
        # Apply status filter
        if filter_status:
            incidents = [i for i in incidents if i.get("status") in filter_status]
        
        # Apply severity filter
        if filter_severity:
            incidents = [i for i in incidents if i.get("severity") in filter_severity]
        
        groups = defaultdict(list)
        
        if group_by == "entity_type":
            for incident in incidents:
                for entity in incident.get("entities", []):
                    group_key = entity.get("type", "unknown")
                    groups[group_key].append(incident)
        
        elif group_by == "entity_id":
            for incident in incidents:
                for entity in incident.get("entities", []):
                    group_key = entity.get("id", "unknown")
                    groups[group_key].append(incident)
        
        elif group_by == "mitre_technique":
            for incident in incidents:
                techniques = incident.get("mitre", [])
                if not techniques:
                    techniques = ["uncategorized"]
                for tech in techniques:
                    groups[tech].append(incident)
        
        elif group_by == "severity":
            for incident in incidents:
                group_key = incident.get("severity", "unknown")
                groups[group_key].append(incident)
        
        elif group_by == "status":
            for incident in incidents:
                group_key = incident.get("status", "unknown")
                groups[group_key].append(incident)
        
        # Sort each group by score
        for group_key in groups:
            groups[group_key].sort(key=lambda x: -x.get("score", 0))
        
        return dict(groups)
    
    def get_related_incidents(self, incident_id: int, relatedness_threshold: float = 0.5) -> List[Dict]:
        """Find incidents related by shared entities or MITRE techniques."""
        incident = self.storage.get_incident(incident_id)
        if not incident:
            return []
        
        base_entities = {(e.get("type"), e.get("id")) for e in incident.get("entities", [])}
        base_mitre = set(incident.get("mitre", []))
        
        all_incidents = self.storage.list_incidents()
        related = []
        
        for other in all_incidents:
            if other.get("id") == incident_id:
                continue
            
            other_entities = {(e.get("type"), e.get("id")) for e in other.get("entities", [])}
            other_mitre = set(other.get("mitre", []))
            
            # Compute similarity
            entity_overlap = len(base_entities & other_entities) / max(len(base_entities | other_entities), 1)
            mitre_overlap = len(base_mitre & other_mitre) / max(len(base_mitre | other_mitre), 1)
            similarity = max(entity_overlap, mitre_overlap)
            
            if similarity >= relatedness_threshold:
                related.append({
                    "incident": other,
                    "similarity": similarity,
                    "relation": "shared_entity" if entity_overlap > mitre_overlap else "shared_technique"
                })
        
        # Sort by similarity
        related.sort(key=lambda x: -x["similarity"])
        return related
    
    def batch_update_status(
        self,
        incident_ids: List[int],
        new_status: str,
        bulk_comment: Optional[str] = None,
        actor: str = "system"
    ) -> Dict[str, int]:
        """Bulk update incident statuses."""
        success = 0
        failed = 0
        
        for incident_id in incident_ids:
            try:
                self.transition_status(incident_id, IncidentStatus(new_status))
                if bulk_comment:
                    self.add_comment(incident_id, bulk_comment, author=actor)
                success += 1
            except Exception as e:
                logger.error(f"batch_update_failed incident_id={incident_id}: {e}")
                failed += 1
        
        logger.info(f"batch_update_status completed success={success} failed={failed}")
        return {"success": success, "failed": failed}
    
    def get_statistics(self) -> Dict:
        """Get incident statistics for dashboard."""
        incidents = self.storage.list_incidents()
        
        stats = {
            "total": len(incidents),
            "by_status": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_mitre": defaultdict(int),
            "avg_score": 0,
            "critical_count": 0,
        }
        
        total_score = 0
        for incident in incidents:
            stats["by_status"][incident.get("status", "unknown")] += 1
            stats["by_severity"][incident.get("severity", "unknown")] += 1
            
            score = incident.get("score", 0)
            total_score += score
            
            if score >= 80:
                stats["critical_count"] += 1
            
            for tech in incident.get("mitre", []):
                stats["by_mitre"][tech] += 1
        
        if incidents:
            stats["avg_score"] = total_score / len(incidents)
        
        # Convert defaultdicts to regular dicts for JSON serialization
        stats["by_status"] = dict(stats["by_status"])
        stats["by_severity"] = dict(stats["by_severity"])
        stats["by_mitre"] = dict(stats["by_mitre"])
        
        return stats
