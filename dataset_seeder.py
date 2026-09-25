"""
Dataset Seeder — SwarmSentinel
================================

Pre-seeds Redis (or the in-memory fallback) with realistic threat-intelligence
data drawn from four public security datasets, bundled as offline snapshots
in the ``datasets/`` directory so the app works without internet access.

Dataset → Scenario mapping
--------------------------
| File                          | Source inspiration      | Scenario             | Redis key(s)              |
|-------------------------------|-------------------------|----------------------|---------------------------|
| phishing_c2_cic_ids.csv       | CIC-IDS2017 / CSE-CIC-IDS2018 | S1 Phishing Mesh     | flagged:phishing_links    |
|                               |                         |                      | pheromone:ip:*            |
| account_takeover_secrepo.csv  | SecRepo SSH/RADIUS      | S2 Account Takeover  | pheromone:user:*          |
| payment_fraud_unsw_nb15.csv   | UNSW-NB15 (public UoNSW)| S3 Payment Fraud     | flagged:upi_ids           |
| benign_baseline_cert.json     | CERT Insider Threat     | S4 Benign Baseline   | detector state (in-memory)|

Architecture
------------
* ``seed_all()`` is the public entry point, called once at application startup
  from ``api/services.py::startup()``.
* All seeding goes through the existing ``storage.add_flagged_intelligence()``,
  ``storage.add_pheromone()``, and ``detectors.run_detectors()`` functions, so
  the Redis ↔ in-memory fallback is handled automatically — no new Redis keys.
* ``clear_redis_state()`` and ``reset_runtime_state()`` in storage.py will
  correctly wipe seeded data because they operate on the same key namespace.
* Seeding is idempotent: Redis SADD / HSET are no-ops for duplicates.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from api.logging_utils import logfmt

logger = logging.getLogger("honeypot.dataset_seeder")

# Base directory for bundled dataset files
_DATASETS_DIR = Path(__file__).parent / "datasets"

# --------------------------------------------------------------------------
# Dataset file names
# --------------------------------------------------------------------------
_CIC_IDS_FILE = _DATASETS_DIR / "phishing_c2_cic_ids.csv"
_SECREPO_FILE = _DATASETS_DIR / "account_takeover_secrepo.csv"
_UNSW_FILE    = _DATASETS_DIR / "payment_fraud_unsw_nb15.csv"
_CERT_FILE    = _DATASETS_DIR / "benign_baseline_cert.json"


# --------------------------------------------------------------------------
# Scenario 1 — CIC-IDS2017 / CSE-CIC-IDS2018 snapshot
# --------------------------------------------------------------------------

def _seed_phishing_c2(dry_run: bool = False) -> Dict[str, int]:
    """
    Reads the CIC-IDS-style snapshot and seeds:
    - ``flagged:phishing_links`` (Redis SADD) from the ``malicious_domain`` column
    - ``pheromone:ip:<src>`` (Redis HSET) for each attack-labelled source IP

    Returns counts of seeded entities.
    """
    import storage

    phishing_links: List[str] = []
    attacker_ips: List[Dict[str, Any]] = []

    try:
        with open(_CIC_IDS_FILE, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                label = row.get("flow_label", "").strip().upper()
                if label != "ATTACK":
                    continue

                domain = row.get("malicious_domain", "").strip()
                if domain:
                    phishing_links.append(f"http://{domain}")

                src_ip = row.get("source_ip", "").strip()
                try:
                    score = float(row.get("risk_score", 50))
                except ValueError:
                    score = 50.0
                attack_type = row.get("attack_type", "unknown").strip()

                if src_ip:
                    attacker_ips.append({
                        "ip": src_ip,
                        "score": score,
                        "attack_type": attack_type,
                    })

    except FileNotFoundError:
        logger.warning(logfmt("seeder_file_missing", file=str(_CIC_IDS_FILE)))
        return {"phishing_links": 0, "attacker_ips": 0}

    if not dry_run:
        # Seed phishing domains into flagged set
        if phishing_links:
            storage.add_flagged_intelligence(phishing_links=phishing_links)

        # Seed attacker IPs as pheromones (scored threat actors)
        for entry in attacker_ips:
            storage.add_pheromone(
                entity_type="ip",
                entity_id=entry["ip"],
                score=entry["score"],
                evidence={
                    "type": "cic_ids_flow",
                    "text": f"CIC-IDS attack flow: {entry['attack_type']}",
                    "source": "CIC-IDS2017/CSE-CIC-IDS2018",
                },
                ts=time.time(),
            )

    logger.info(
        logfmt(
            "seeder_cic_ids_done",
            phishing_links=len(phishing_links),
            attacker_ips=len(attacker_ips),
            dry_run=dry_run,
        )
    )
    return {"phishing_links": len(phishing_links), "attacker_ips": len(attacker_ips)}


# --------------------------------------------------------------------------
# Scenario 2 — SecRepo SSH / RADIUS auth logs
# --------------------------------------------------------------------------

def _seed_account_takeover(dry_run: bool = False) -> Dict[str, int]:
    """
    Reads the SecRepo-style auth log and seeds:
    - ``pheromone:user:<username>`` for each user with FAILURE entries
    - ``pheromone:ip:<source_ip>`` for each attacking IP

    The score is derived from the number of failures per entity.
    """
    import storage

    user_failures: Dict[str, Dict[str, Any]] = {}
    ip_failures: Dict[str, Dict[str, Any]] = {}

    try:
        with open(_SECREPO_FILE, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                result = row.get("auth_result", "").strip().upper()
                if result != "FAILURE":
                    continue

                username = row.get("username", "").strip()
                src_ip = row.get("source_ip", "").strip()
                country = row.get("country", "").strip()
                city = row.get("city", "").strip()
                reason = row.get("failure_reason", "unknown").strip()

                # Accumulate per-user failure data
                if username:
                    rec = user_failures.setdefault(username, {"count": 0, "reasons": set(), "ips": set()})
                    rec["count"] += 1
                    rec["reasons"].add(reason)
                    if src_ip:
                        rec["ips"].add(src_ip)

                # Accumulate per-IP failure data
                if src_ip:
                    rec = ip_failures.setdefault(src_ip, {"count": 0, "countries": set(), "users": set()})
                    rec["count"] += 1
                    if country:
                        rec["countries"].add(country)
                    if username:
                        rec["users"].add(username)

    except FileNotFoundError:
        logger.warning(logfmt("seeder_file_missing", file=str(_SECREPO_FILE)))
        return {"users_seeded": 0, "ips_seeded": 0}

    if not dry_run:
        # Seed per-user pheromones (scale: 1 failure=10pts, cap at 95)
        for username, data in user_failures.items():
            score = min(95, data["count"] * 10)
            storage.add_pheromone(
                entity_type="user",
                entity_id=username,
                score=score,
                evidence={
                    "type": "auth_failure",
                    "text": (
                        f"SecRepo: {data['count']} failed auth attempts. "
                        f"Reasons: {', '.join(list(data['reasons'])[:3])}. "
                        f"From {len(data['ips'])} unique IPs."
                    ),
                    "source": "SecRepo-SSH-RADIUS",
                },
                ts=time.time(),
            )

        # Seed per-IP pheromones from the auth log
        for ip, data in ip_failures.items():
            score = min(90, data["count"] * 8)
            storage.add_pheromone(
                entity_type="ip",
                entity_id=ip,
                score=score,
                evidence={
                    "type": "brute_force",
                    "text": (
                        f"SecRepo: {data['count']} auth failures originating from this IP. "
                        f"Targeted users: {', '.join(list(data['users'])[:3])}. "
                        f"Countries: {', '.join(list(data['countries'])[:3])}."
                    ),
                    "source": "SecRepo-SSH-RADIUS",
                },
                ts=time.time(),
            )

    logger.info(
        logfmt(
            "seeder_secrepo_done",
            users_seeded=len(user_failures),
            ips_seeded=len(ip_failures),
            dry_run=dry_run,
        )
    )
    return {"users_seeded": len(user_failures), "ips_seeded": len(ip_failures)}


# --------------------------------------------------------------------------
# Scenario 3 — UNSW-NB15 (no Kaggle required)
# --------------------------------------------------------------------------

def _seed_payment_fraud(dry_run: bool = False) -> Dict[str, int]:
    """
    Reads the UNSW-NB15-style snapshot and seeds:
    - ``flagged:upi_ids`` with the ``financial_proxy_id`` column (attack rows only)
    - ``pheromone:ip:<src_ip>`` for high-score attack source IPs

    UNSW-NB15 is publicly available from the University of New South Wales
    (research.unsw.edu.au/projects/unsw-nb15-dataset) — no Kaggle account needed.
    """
    import storage

    fraud_tx_ids: List[str] = []
    attacker_ips: List[Dict[str, Any]] = []

    try:
        with open(_UNSW_FILE, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    label = int(row.get("label", 0))
                except ValueError:
                    label = 0
                if label != 1:
                    continue

                tx_id = row.get("financial_proxy_id", "").strip()
                if tx_id:
                    fraud_tx_ids.append(tx_id)

                src_ip = row.get("src_ip", "").strip()
                try:
                    score = float(row.get("attack_score", 60))
                except ValueError:
                    score = 60.0
                attack_cat = row.get("attack_cat", "unknown").strip()

                if src_ip and score >= 80:   # only seed high-confidence attackers
                    attacker_ips.append({
                        "ip": src_ip,
                        "score": score,
                        "category": attack_cat,
                    })

    except FileNotFoundError:
        logger.warning(logfmt("seeder_file_missing", file=str(_UNSW_FILE)))
        return {"fraud_tx_ids": 0, "attacker_ips": 0}

    if not dry_run:
        if fraud_tx_ids:
            storage.add_flagged_intelligence(upi_ids=fraud_tx_ids)

        for entry in attacker_ips:
            storage.add_pheromone(
                entity_type="ip",
                entity_id=entry["ip"],
                score=entry["score"],
                evidence={
                    "type": "unsw_nb15_attack",
                    "text": f"UNSW-NB15 high-confidence attack: category={entry['category']}",
                    "source": "UNSW-NB15",
                },
                ts=time.time(),
            )

    logger.info(
        logfmt(
            "seeder_unsw_done",
            fraud_tx_ids=len(fraud_tx_ids),
            high_risk_ips=len(attacker_ips),
            dry_run=dry_run,
        )
    )
    return {"fraud_tx_ids": len(fraud_tx_ids), "attacker_ips": len(attacker_ips)}


# --------------------------------------------------------------------------
# Scenario 4 — CERT Insider Threat benign baseline
# --------------------------------------------------------------------------

def _seed_benign_baseline(dry_run: bool = False) -> Dict[str, int]:
    """
    Reads the CERT-style benign baseline JSON and warms the ZScoreDetector's
    ``_detector_state`` history for each user.

    Because ``_detector_state`` is an in-memory dict in ``detectors.py`` (not
    persisted to Redis), this warm-up is always applied regardless of backend.
    It ensures the ZScore baseline is populated so the first real attack events
    produce a meaningful anomaly signal rather than "insufficient history".
    """
    from detectors import run_detectors

    events_processed = 0
    base_ts = time.time()

    try:
        with open(_CERT_FILE, encoding="utf-8") as fh:
            records = json.load(fh)
    except FileNotFoundError:
        logger.warning(logfmt("seeder_file_missing", file=str(_CERT_FILE)))
        return {"baseline_events": 0}
    except json.JSONDecodeError as exc:
        logger.error(logfmt("seeder_cert_json_error", error=str(exc)))
        return {"baseline_events": 0}

    if not dry_run:
        for record in records:
            username = record.get("user", "unknown")
            score = float(record.get("score", 5))
            ts_offset = float(record.get("ts_offset", 0))
            activity = record.get("activity", "unknown")
            resource = record.get("resource", "unknown")

            synthetic_event = {
                "entity_type": "user",
                "entity_id": username,
                "score": score,
                "evidence": [
                    {
                        "type": activity,
                        "text": f"CERT baseline: {activity} on {resource}",
                        "source": "CERT-InsiderThreat",
                    }
                ],
                "ts": base_ts - (86400 * 30) + ts_offset,  # 30 days ago
            }
            try:
                run_detectors(synthetic_event)
                events_processed += 1
            except Exception as exc:
                logger.debug(logfmt("seeder_cert_event_error", error=str(exc)))

    logger.info(
        logfmt(
            "seeder_cert_done",
            baseline_events=events_processed,
            dry_run=dry_run,
        )
    )
    return {"baseline_events": events_processed}


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

class DatasetSeeder:
    """
    Orchestrates the four dataset seeding operations.

    Usage::

        seeder = DatasetSeeder()
        result = seeder.seed_all()
        # result is a dict with per-scenario counts

    The seeder is idempotent — calling it multiple times only adds new
    entries to Redis sets; duplicates are silently ignored by SADD.
    """

    def seed_all(self, dry_run: bool = False) -> Dict[str, Any]:
        """Run all four dataset seeders.

        Parameters
        ----------
        dry_run:
            If True, parse datasets and compute counts but do NOT write to
            Redis or in-memory state.  Useful for startup validation.

        Returns
        -------
        dict
            Per-scenario entity counts for logging / health endpoints.
        """
        logger.info(logfmt("dataset_seeder_start", dry_run=dry_run))
        results: Dict[str, Any] = {}

        # S1: CIC-IDS2017 / CSE-CIC-IDS2018
        try:
            results["scenario1_phishing_c2"] = _seed_phishing_c2(dry_run=dry_run)
        except Exception as exc:
            logger.error(logfmt("seeder_s1_failed", error=str(exc)))
            results["scenario1_phishing_c2"] = {"error": str(exc)}

        # S2: SecRepo auth logs
        try:
            results["scenario2_account_takeover"] = _seed_account_takeover(dry_run=dry_run)
        except Exception as exc:
            logger.error(logfmt("seeder_s2_failed", error=str(exc)))
            results["scenario2_account_takeover"] = {"error": str(exc)}

        # S3: UNSW-NB15
        try:
            results["scenario3_payment_fraud"] = _seed_payment_fraud(dry_run=dry_run)
        except Exception as exc:
            logger.error(logfmt("seeder_s3_failed", error=str(exc)))
            results["scenario3_payment_fraud"] = {"error": str(exc)}

        # S4: CERT baseline (always in-memory warm-up)
        try:
            results["scenario4_benign_baseline"] = _seed_benign_baseline(dry_run=dry_run)
        except Exception as exc:
            logger.error(logfmt("seeder_s4_failed", error=str(exc)))
            results["scenario4_benign_baseline"] = {"error": str(exc)}

        logger.info(logfmt("dataset_seeder_complete", results=results, dry_run=dry_run))
        return results

    def validate(self) -> Dict[str, bool]:
        """Check that all bundled dataset files exist and are non-empty.

        Returns
        -------
        dict
            Mapping of dataset name → bool (True if file is present and non-empty).
        """
        files = {
            "phishing_c2_cic_ids": _CIC_IDS_FILE,
            "account_takeover_secrepo": _SECREPO_FILE,
            "payment_fraud_unsw_nb15": _UNSW_FILE,
            "benign_baseline_cert": _CERT_FILE,
        }
        result = {}
        for name, path in files.items():
            exists = path.exists() and path.stat().st_size > 0
            result[name] = exists
            if not exists:
                logger.warning(logfmt("seeder_validate_missing", dataset=name, path=str(path)))
        return result


# Module-level singleton
dataset_seeder = DatasetSeeder()


def seed_all(dry_run: bool = False) -> Dict[str, Any]:
    """Top-level convenience function for use in startup hooks."""
    return dataset_seeder.seed_all(dry_run=dry_run)
