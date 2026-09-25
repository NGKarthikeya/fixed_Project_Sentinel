"""
Containment Engine — SwarmSentinel
====================================

Provides actionable containment responses that SOC analysts can trigger
from the dashboard. Each action is logged to an immutable audit trail
and broadcast via WebSocket for real-time visibility.

Supported actions:
- block_ip: Add IP to blocklist with TTL
- isolate_host: Mark host as quarantined
- disable_user: Flag user account for suspension
- escalate: Generate escalation ticket
- acknowledge: Mark incident as acknowledged

All actions are LOGGED, not enforced — this is a detection system.
In production, these would integrate with firewall APIs, AD, or SOAR.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from api.logging_utils import logfmt

from api.logging_utils import logfmt

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    ESCALATE = "escalate"
    ACKNOWLEDGE = "acknowledge"
    RELEASE = "release"


class ActionStatus(str, Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ContainmentAction:
    """A single containment action taken on an entity."""
    id: int
    action: ActionType
    entity_id: str
    entity_type: str
    actor: str
    reason: str
    incident_id: Optional[int]
    status: ActionStatus
    timestamp: float
    ttl_seconds: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action.value,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "actor": self.actor,
            "reason": self.reason,
            "incident_id": self.incident_id,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "ttl_seconds": self.ttl_seconds,
            "metadata": self.metadata,
        }


class ContainmentEngine:
    """Manages containment actions and maintains the blocklist/audit trail."""

    def __init__(self) -> None:
        self._actions: List[ContainmentAction] = []
        self._blocklist: Dict[str, ContainmentAction] = {}  # entity_id → action
        self._isolated_hosts: Dict[str, ContainmentAction] = {}
        self._disabled_users: Dict[str, ContainmentAction] = {}
        self._next_id = 1

    def execute_action(
        self,
        action: str,
        entity_id: str,
        entity_type: str = "ip",
        actor: str = "analyst",
        reason: str = "",
        incident_id: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a containment action.

        Parameters
        ----------
        action : str
            Action type (block_ip, isolate_host, disable_user, escalate, acknowledge, release).
        entity_id : str
            Target entity identifier.
        entity_type : str
            Entity category (ip, host, user, domain).
        actor : str
            Who initiated the action.
        reason : str
            Justification for the action.
        incident_id : int, optional
            Related incident.
        ttl_seconds : int, optional
            Auto-release after this many seconds (for block_ip).
        metadata : dict, optional
            Additional context.

        Returns
        -------
        dict
            Action result with status and details.
        """
        try:
            action_type = ActionType(action)
        except ValueError:
            return {"status": "error", "message": f"Unknown action: {action}"}

        record = ContainmentAction(
            id=self._next_id,
            action=action_type,
            entity_id=entity_id,
            entity_type=entity_type,
            actor=actor,
            reason=reason,
            incident_id=incident_id,
            status=ActionStatus.PENDING,
            timestamp=time.time(),
            ttl_seconds=ttl_seconds,
            metadata=metadata or {},
        )
        self._next_id += 1

        # Execute the action
        result = self._dispatch(record)
        self._actions.append(record)

        logger.info(logfmt(
            "containment_action",
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            status=record.status.value
        ))

        return {
            "status": "ok",
            "action": record.to_dict(),
            "result": result,
        }

    def _dispatch(self, action: ContainmentAction) -> Dict[str, Any]:
        """Route action to the appropriate handler."""
        handlers = {
            ActionType.BLOCK_IP: self._block_ip,
            ActionType.ISOLATE_HOST: self._isolate_host,
            ActionType.DISABLE_USER: self._disable_user,
            ActionType.ESCALATE: self._escalate,
            ActionType.ACKNOWLEDGE: self._acknowledge,
            ActionType.RELEASE: self._release,
        }
        handler = handlers.get(action.action)
        if handler:
            return handler(action)
        action.status = ActionStatus.FAILED
        return {"error": "No handler for action"}

    def _block_ip(self, action: ContainmentAction) -> Dict[str, Any]:
        self._blocklist[action.entity_id] = action
        action.status = ActionStatus.EXECUTED
        return {
            "blocked": action.entity_id,
            "ttl": action.ttl_seconds,
            "note": "IP added to blocklist (logged — enforcement via firewall integration)",
        }

    def _isolate_host(self, action: ContainmentAction) -> Dict[str, Any]:
        self._isolated_hosts[action.entity_id] = action
        action.status = ActionStatus.EXECUTED
        return {
            "isolated": action.entity_id,
            "note": "Host marked for isolation (logged — enforcement via EDR integration)",
        }

    def _disable_user(self, action: ContainmentAction) -> Dict[str, Any]:
        self._disabled_users[action.entity_id] = action
        action.status = ActionStatus.EXECUTED
        return {
            "disabled": action.entity_id,
            "note": "User flagged for suspension (logged — enforcement via IAM integration)",
        }

    def _escalate(self, action: ContainmentAction) -> Dict[str, Any]:
        action.status = ActionStatus.EXECUTED
        return {
            "escalated": True,
            "incident_id": action.incident_id,
            "note": "Escalation ticket generated (logged — SOAR integration pending)",
        }

    def _acknowledge(self, action: ContainmentAction) -> Dict[str, Any]:
        action.status = ActionStatus.EXECUTED
        return {"acknowledged": action.entity_id}

    def _release(self, action: ContainmentAction) -> Dict[str, Any]:
        """Remove entity from blocklist/isolation."""
        released_from = []
        if action.entity_id in self._blocklist:
            del self._blocklist[action.entity_id]
            released_from.append("blocklist")
        if action.entity_id in self._isolated_hosts:
            del self._isolated_hosts[action.entity_id]
            released_from.append("isolation")
        if action.entity_id in self._disabled_users:
            del self._disabled_users[action.entity_id]
            released_from.append("disabled_users")
        action.status = ActionStatus.EXECUTED
        return {"released": action.entity_id, "from": released_from}

    def is_blocked(self, entity_id: str) -> bool:
        """Check if an entity is on the blocklist."""
        if entity_id not in self._blocklist:
            return False
        action = self._blocklist[entity_id]
        # Check TTL
        if action.ttl_seconds is not None:
            if time.time() - action.timestamp > action.ttl_seconds:
                del self._blocklist[entity_id]
                return False
        return True

    def get_blocklist(self) -> List[Dict[str, Any]]:
        """Return current blocklist."""
        # Clean expired entries
        now = time.time()
        expired = [
            eid for eid, a in self._blocklist.items()
            if a.ttl_seconds is not None and (now - a.timestamp > a.ttl_seconds)
        ]
        for eid in expired:
            del self._blocklist[eid]

        return [a.to_dict() for a in self._blocklist.values()]

    def get_audit_trail(self, entity_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Return audit trail, optionally filtered by entity."""
        actions = self._actions
        if entity_id:
            actions = [a for a in actions if a.entity_id == entity_id]
        return [a.to_dict() for a in sorted(actions, key=lambda a: a.timestamp, reverse=True)[:limit]]

    def stats(self) -> Dict[str, Any]:
        return {
            "total_actions": len(self._actions),
            "blocked_ips": len(self._blocklist),
            "isolated_hosts": len(self._isolated_hosts),
            "disabled_users": len(self._disabled_users),
            "by_action": {
                at.value: sum(1 for a in self._actions if a.action == at)
                for at in ActionType
            },
        }

    def reset(self) -> None:
        self._actions.clear()
        self._blocklist.clear()
        self._isolated_hosts.clear()
        self._disabled_users.clear()
        self._next_id = 1
        logger.info(logfmt("containment_state_reset"))


# Module-level singleton
containment_engine = ContainmentEngine()
