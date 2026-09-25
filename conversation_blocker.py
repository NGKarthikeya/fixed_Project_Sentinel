"""
Conversation blocking logic - decides when to end honeypot conversation
and send blocked message instead of engaging further.
"""
import logging
from typing import List, Dict
from lifecycle import ScamPhase

logger = logging.getLogger("honeypot.blocker")

# Blocked messages (hardcoded options for different scenarios)
BLOCKED_MESSAGES = {
    "payment_repeated": "Your account has been flagged for suspicious activity. This conversation has been recorded and reported to authorities.",
    "escalation_threats": "This number has been reported for fraud. Your account access is now restricted. Do not contact this number again.",
    "max_turns": "Your device has been flagged. Contact your bank immediately for verification.",
    "payment_urgency": "This is a spam number. Your account is now protected. Police have been notified.",
    "default": "Your account has been temporarily locked due to suspicious activity. Please contact your bank."
}


def should_block_conversation(
    history: List[Dict],
    phase: ScamPhase,
    confidence: float
) -> tuple:
    """
    Determine if honeypot should stop engaging and send blocking message instead.
    
    Returns: (should_block: bool, blocked_message: str or None)
    """
    
    if not history:
        return False, None
    
    # Count conversation turns
    scammer_turns = len([m for m in history if m["role"] == "scammer"])
    honeypot_turns = len([m for m in history if m["role"] == "honeypot"])
    
    # Combine all scammer messages for analysis
    scammer_text = " ".join(
        m["content"].lower() for m in history if m["role"] == "scammer"
    )
    
    logger.info(f"🔍 Checking block conditions: turns={scammer_turns}, phase={phase.value}, confidence={confidence}")
    
    # ❌ CONDITION 1: Payment repeated with very high confidence
    payment_keywords = ["upi", "paytm", "googlepay", "phonepay", "transfer", "send money", "pay"]
    threat_keywords = ["immediate", "urgent", "now", "right now", "police", "freeze", "block"]
    
    payment_mentions = sum(1 for msg in history if msg["role"] == "scammer" and any(kw in msg["content"].lower() for kw in payment_keywords))
    threat_mentions = sum(1 for msg in history if msg["role"] == "scammer" and any(kw in msg["content"].lower() for kw in threat_keywords))
    
    # Block if payment asked multiple times + high confidence
    if payment_mentions >= 2 and confidence >= 0.95:
        logger.warning(f"🛑 BLOCKING: Payment asked {payment_mentions} times with confidence {confidence}")
        return True, BLOCKED_MESSAGES.get("payment_repeated")
    
    # ❌ CONDITION 2: Extreme threats + escalation phase + high confidence
    if phase == ScamPhase.EXIT and threat_mentions >= 2 and confidence >= 0.9:
        logger.warning(f"🛑 BLOCKING: EXIT phase with extreme threats and high confidence")
        return True, BLOCKED_MESSAGES.get("escalation_threats")
    
    # ❌ CONDITION 3: Conversation too long (10+ turns by scammer = persistence)
    if scammer_turns >= 10:
        logger.warning(f"🛑 BLOCKING: Conversation too long ({scammer_turns} scammer turns)")
        return True, BLOCKED_MESSAGES.get("max_turns")
    
    # ❌ CONDITION 4: Payment urgency combined with reaching escalation
    payment_and_urgent = any(
        ("pay" in m["content"].lower() or "upi" in m["content"].lower()) and 
        ("urgent" in m["content"].lower() or "now" in m["content"].lower())
        for m in history if m["role"] == "scammer"
    )
    
    if payment_and_urgent and phase in [ScamPhase.ESCALATION, ScamPhase.EXIT]:
        logger.warning(f"🛑 BLOCKING: Payment urgency in escalation phase")
        return True, BLOCKED_MESSAGES.get("payment_urgency")
    
    # ✅ No blocking conditions met
    logger.info("✅ No blocking conditions met - continue conversation")
    return False, None
