from __future__ import annotations

import json
import logging
import os
import time
from typing import Dict, List, Optional

import redis
import redis.backoff
import redis.retry

from api.logging_utils import logfmt
from forensic.report_models import EvidenceMetadata
from lifecycle import ScamPhase

logger = logging.getLogger("honeypot.storage")

_memory_store: dict[str, str] = {}
_flagged_upi_ids: set[str] = set()
_flagged_bank_accounts: set[str] = set()
_flagged_phishing_links: set[str] = set()
_pheromones: dict[str, dict] = {}
_incidents: dict[int, dict] = {}
_audit_logs: dict[int, list] = {}
_evidence_store: dict[str, dict] = {}
_email_analysis_store: dict[str, dict] = {}
_next_incident_id = 1

_REDIS_KEYS = {
    "flagged:upi_ids",
    "flagged:bank_accounts",
    "flagged:phishing_links",
    "pheromone:entities",
    "incidents",
    "incident:next_id",
}


def _is_placeholder_url(url: Optional[str]) -> bool:
    return bool(url and ("YOUR_UPSTASH" in url or "YOUR_API_KEY" in url))


_no_retry = redis.retry.Retry(redis.backoff.NoBackoff(), 0)


def _build_redis_client():
    redis_url = os.getenv("REDIS_URL")
    options = {
        "decode_responses": True,
        "socket_connect_timeout": 0.2,
        "socket_timeout": 0.2,
        "retry": _no_retry,
    }
    if redis_url and not _is_placeholder_url(redis_url):
        return redis.Redis.from_url(redis_url, **options)
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD"),
        **options,
    )


redis_client = _build_redis_client()


def _redis_available() -> bool:
    try:
        redis_client.ping()
        return True
    except Exception as exc:
        logger.debug(logfmt("storage_redis_unavailable", error=exc))
        return False


def storage_backend() -> str:
    return "redis" if _redis_available() else "memory"


def _load_json(data: Optional[str], default):
    if not data:
        return default
    try:
        return json.loads(data)
    except Exception:
        return default


def get_conversation(conversation_id: str):
    data = redis_client.get(conversation_id) if _redis_available() else _memory_store.get(conversation_id)
    if not data:
        return None
    obj = _load_json(data, None)
    if not obj:
        return None
    obj["phase"] = ScamPhase(obj["phase"])
    return obj


def save_conversation(conversation_id: str, state: dict):
    payload = json.dumps({"phase": state["phase"].value, "messages": state["messages"]})
    if _redis_available():
        redis_client.set(conversation_id, payload)
    else:
        _memory_store[conversation_id] = payload


def add_flagged_intelligence(
    upi_ids: List[str] = None,
    bank_accounts: List[str] = None,
    phishing_links: List[str] = None,
):
    upi_ids = upi_ids or []
    bank_accounts = bank_accounts or []
    phishing_links = phishing_links or []

    if _redis_available():
        if upi_ids:
            redis_client.sadd("flagged:upi_ids", *upi_ids)
        if bank_accounts:
            redis_client.sadd("flagged:bank_accounts", *bank_accounts)
        if phishing_links:
            redis_client.sadd("flagged:phishing_links", *phishing_links)
    else:
        _flagged_upi_ids.update(upi_ids)
        _flagged_bank_accounts.update(bank_accounts)
        _flagged_phishing_links.update(phishing_links)

    logger.info(
        logfmt(
            "flagged_intelligence_added",
            backend=storage_backend(),
            upi_ids=len(upi_ids),
            bank_accounts=len(bank_accounts),
            phishing_links=len(phishing_links),
        )
    )


def check_flagged_intelligence(extracted_intelligence: Dict) -> tuple:
    if not extracted_intelligence:
        return False, ""

    upi_ids = extracted_intelligence.get("upi_ids", [])
    bank_accounts = extracted_intelligence.get("bank_accounts", [])
    phishing_links = extracted_intelligence.get("phishing_links", [])

    if _redis_available():
        checks = [
            ("flagged:upi_ids", upi_ids, "UPI ID {value} has been flagged as suspicious in previous scams"),
            ("flagged:bank_accounts", bank_accounts, "Bank account {value} has been flagged as suspicious"),
            ("flagged:phishing_links", phishing_links, "Phishing link {value} has been reported multiple times"),
        ]
        for key, values, message in checks:
            for value in values:
                if redis_client.sismember(key, value):
                    logger.warning(logfmt("flagged_intelligence_match", backend="redis", key=key, value=value))
                    return True, message.format(value=value)
    else:
        in_memory_sets = [
            (_flagged_upi_ids, upi_ids, "UPI ID {value} has been flagged as suspicious in previous scams"),
            (_flagged_bank_accounts, bank_accounts, "Bank account {value} has been flagged as suspicious"),
            (_flagged_phishing_links, phishing_links, "Phishing link {value} has been reported multiple times"),
        ]
        for values_set, values, message in in_memory_sets:
            for value in values:
                if value in values_set:
                    logger.warning(logfmt("flagged_intelligence_match", backend="memory", value=value))
                    return True, message.format(value=value)

    return False, ""


def get_flagged_intelligence_stats() -> Dict:
    if _redis_available():
        upi_count = redis_client.scard("flagged:upi_ids")
        account_count = redis_client.scard("flagged:bank_accounts")
        link_count = redis_client.scard("flagged:phishing_links")
    else:
        upi_count = len(_flagged_upi_ids)
        account_count = len(_flagged_bank_accounts)
        link_count = len(_flagged_phishing_links)
    return {
        "backend": storage_backend(),
        "flagged_upi_ids_count": upi_count,
        "flagged_bank_accounts_count": account_count,
        "flagged_phishing_links_count": link_count,
        "total_flagged": upi_count + account_count + link_count,
    }


def add_pheromone(entity_type: str, entity_id: str, score: float, evidence: dict, ts: float = None):
    global _pheromones
    ts = ts or time.time()
    key = f"{entity_type}:{entity_id}"
    if _redis_available():
        redis_client.hset(f"pheromone:{key}", mapping={"score": score, "ts": ts, "evidence": json.dumps(evidence)})
        redis_client.sadd("pheromone:entities", key)
        _REDIS_KEYS.add(f"pheromone:{key}")
        return

    current = _pheromones.get(key, {"score": 0.0, "ts": ts, "evidence": []})
    current["score"] = min(100, current.get("score", 0.0) + score)
    current["ts"] = ts
    current.setdefault("evidence", []).append(evidence)
    _pheromones[key] = current


def get_pheromones_snapshot():
    out = []
    if _redis_available():
        for key in sorted(redis_client.smembers("pheromone:entities")):
            data = redis_client.hgetall(f"pheromone:{key}")
            if not data:
                continue
            entity_type, entity_id = key.split(":", 1)
            out.append(
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "score": float(data.get("score", 0)),
                    "evidence": _load_json(data.get("evidence", "[]"), []),
                    "ts": float(data.get("ts", 0)),
                }
            )
        return out

    for key in sorted(_pheromones):
        value = _pheromones[key]
        entity_type, entity_id = key.split(":", 1)
        out.append(
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "score": float(value.get("score", 0)),
                "evidence": value.get("evidence", []),
                "ts": float(value.get("ts", 0)),
            }
        )
    return out


def create_incident(incident: dict) -> int:
    global _next_incident_id
    if _redis_available():
        incident_id = int(redis_client.incr("incident:next_id"))
        incident["id"] = incident_id
        redis_client.set(f"incident:{incident_id}", json.dumps(incident))
        redis_client.lpush("incidents", incident_id)
        _REDIS_KEYS.update({f"incident:{incident_id}", f"incident:{incident_id}:audit"})
        return incident_id

    incident_id = _next_incident_id
    _next_incident_id += 1
    incident["id"] = incident_id
    _incidents[incident_id] = incident
    _audit_logs.setdefault(incident_id, [])
    return incident_id


def get_incident(incident_id: int) -> Optional[dict]:
    if _redis_available():
        return _load_json(redis_client.get(f"incident:{incident_id}"), None)
    return _incidents.get(int(incident_id))

def save_evidence_metadata(email_id: str, evidence: EvidenceMetadata) -> None:
    """Persist forensic evidence metadata using the active storage backend."""
    payload = evidence.model_dump(mode="json")
    if _redis_available():
        key = f"email:{email_id}:evidence"
        redis_client.set(key, json.dumps(payload))
        _REDIS_KEYS.add(key)
    else:
        _evidence_store[email_id] = payload


async def save_evidence_metadata_async(email_id: str, evidence: EvidenceMetadata) -> None:
    save_evidence_metadata(email_id, evidence)


def get_evidence_metadata(email_id: str) -> Optional[EvidenceMetadata]:
    raw = redis_client.get(f"email:{email_id}:evidence") if _redis_available() else None
    data = json.loads(raw) if raw else _evidence_store.get(email_id)
    return EvidenceMetadata.model_validate(data) if data else None


async def get_evidence_metadata_async(email_id: str) -> Optional[EvidenceMetadata]:
    return get_evidence_metadata(email_id)


def save_email_analysis(email_id: str, analysis: dict) -> None:
    if _redis_available():
        key = f"email:{email_id}:analysis"
        redis_client.set(key, json.dumps(analysis, default=str))
        _REDIS_KEYS.add(key)
    else:
        _email_analysis_store[email_id] = analysis


async def save_email_analysis_async(email_id: str, analysis: dict) -> None:
    save_email_analysis(email_id, analysis)


def get_email_analysis(email_id: str):
    raw = redis_client.get(f"email:{email_id}:analysis") if _redis_available() else None
    return json.loads(raw) if raw else _email_analysis_store.get(email_id)


async def get_email_analysis_async(email_id: str):
    return get_email_analysis(email_id)


def log_report_generation(event_type: str, email_id: str, actor: str, report_id: str) -> dict:
    event = {"event_type": event_type, "email_id": email_id, "actor": actor, "report_id": report_id, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if _redis_available():
        redis_client.lpush("audit:report", json.dumps(event))
    else:
        _audit_logs.setdefault(-1, []).append(event)
    return event

def list_incidents() -> list:
    if _redis_available():
        ids = redis_client.lrange("incidents", 0, 50)
        incidents = []
        for incident_id in ids:
            data = redis_client.get(f"incident:{incident_id}")
            if data:
                incidents.append(json.loads(data))
        return incidents
    return [incident for _, incident in sorted(_incidents.items(), key=lambda item: item[0], reverse=True)]


def add_audit_log(incident_id: int, entry: dict):
    entry = {"incident_id": int(incident_id), **entry}
    if _redis_available():
        redis_client.lpush(f"incident:{incident_id}:audit", json.dumps(entry))
        _REDIS_KEYS.add(f"incident:{incident_id}:audit")
        return
    _audit_logs.setdefault(int(incident_id), []).append(entry)


def get_audit_log(incident_id: int) -> list:
    if _redis_available():
        return [json.loads(item) for item in redis_client.lrange(f"incident:{incident_id}:audit", 0, 100)]
    return list(_audit_logs.get(int(incident_id), []))


def update_incident(incident_id: int, updates: dict) -> Optional[dict]:
    if _redis_available():
        data = redis_client.get(f"incident:{incident_id}")
        if not data:
            return None
        incident = json.loads(data)
        incident.update(updates)
        redis_client.set(f"incident:{incident_id}", json.dumps(incident))
        return incident

    incident = _incidents.get(int(incident_id))
    if not incident:
        return None
    incident.update(updates)
    _incidents[int(incident_id)] = incident
    return incident


def clear_redis_state() -> bool:
    if not _redis_available():
        return False
    keys_to_delete = set(_REDIS_KEYS)
    pheromone_entities = redis_client.smembers("pheromone:entities")
    for entity_key in pheromone_entities:
        keys_to_delete.add(f"pheromone:{entity_key}")
    incident_ids = redis_client.lrange("incidents", 0, -1)
    for incident_id in incident_ids:
        keys_to_delete.update({f"incident:{incident_id}", f"incident:{incident_id}:audit"})
    if keys_to_delete:
        redis_client.delete(*sorted(keys_to_delete))
    return True


def reset_runtime_state(clear_redis: bool = False):
    global _next_incident_id
    _memory_store.clear()
    _flagged_upi_ids.clear()
    _flagged_bank_accounts.clear()
    _flagged_phishing_links.clear()
    _pheromones.clear()
    _incidents.clear()
    _audit_logs.clear()
    _evidence_store.clear()
    _email_analysis_store.clear()
    _next_incident_id = 1

    redis_cleared = False
    if clear_redis:
        redis_cleared = clear_redis_state()

    logger.info(logfmt("storage_reset", backend=storage_backend(), redis_cleared=redis_cleared))


def storage_stats() -> Dict[str, object]:
    return {
        "backend": storage_backend(),
        "conversations": len(_memory_store),
        "flagged_total": len(_flagged_upi_ids) + len(_flagged_bank_accounts) + len(_flagged_phishing_links),
        "pheromones": len(_pheromones),
        "incidents": len(_incidents),
        "audit_logs": sum(len(items) for items in _audit_logs.values()),
    }


clear_all_state = reset_runtime_state
