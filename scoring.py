# scoring.py
from typing import Dict, Optional
from lifecycle import ScamPhase


def compute_risk_score(
    detection,
    fingerprint: Dict,
    phase: ScamPhase,
    intelligence,
    forensic_signals: Optional[Dict] = None,
) -> Dict:
    """
    Returns a normalized risk assessment.
    """

    score = 0

    # Detection confidence
    if detection.is_scam:
        score += int(detection.confidence * 40)

    # Behavioral signals
    if fingerprint.get("pressure_language"):
        score += 15

    if fingerprint.get("links_shared"):
        score += 20

    if fingerprint.get("payment_intent"):
        score += 15

    if fingerprint.get("message_count", 0) > 3:
        score += 10

    # Lifecycle escalation
    if phase in {ScamPhase.ESCALATION, ScamPhase.PAYMENT}:
        score += 20

    # Intelligence evidence
    if intelligence:
        if intelligence.upi_ids:
            score += 15
        if intelligence.phishing_links:
            score += 20

    forensic_signals = forensic_signals or {}
    forensic_weights = {
        "header_anomaly": 8,
        "authentication_failure": 12,
        "alignment_failure": 10,
        "geo_anomaly": 8,
        "domain_reputation": 10,
        "brand_spoof": 18,
    }
    contributions = {}
    for signal, weight in forensic_weights.items():
        if forensic_signals.get(signal):
            score += weight
            contributions[signal] = weight

    score = min(score, 100)

    if score >= 75:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "forensic_contributions": contributions,
    }