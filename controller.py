# controller.py - UPDATED TO USE LLM REPLIES
import logging
from schemas import ScamAnalysisResponse
from intelligence import detect_scam, extract_intelligence
from storage import (
    get_conversation, 
    save_conversation,
    add_flagged_intelligence,
    check_flagged_intelligence
)
from lifecycle import ScamPhase
from phase_engine import next_phase
from ai_honeypot import generate_honeypot_reply  # USES YOUR EXISTING FILE with LLM!
from scoring import compute_risk_score
from fingerprint import analyze_attacker
from conversation_blocker import should_block_conversation

logger = logging.getLogger("honeypot.controller")


def handle_message(
    conversation_id: str,
    message: str,
    ip: str | None = None,
    user_agent: str | None = None
) -> ScamAnalysisResponse:

    # 1️⃣ Load or initialize conversation state
    state = get_conversation(conversation_id)

    if not state:
        state = {
            "phase": ScamPhase.INITIAL,
            "messages": []
        }

    # 🔒 ENUM-SAFE PHASE HANDLING (CRITICAL FIX)
    raw_phase = state.get("phase", ScamPhase.INITIAL)
    if isinstance(raw_phase, ScamPhase):
        current_phase = raw_phase
    else:
        current_phase = ScamPhase(raw_phase)

    history = state.get("messages", [])

    # 2️⃣ Save scammer message
    history.append({
        "role": "scammer",
        "content": message
    })

    # 3️⃣ Detection + intelligence (history-aware)
    scammer_text = " ".join(
        m["content"] for m in history if m["role"] == "scammer"
    )

    detection = detect_scam(scammer_text)
    intelligence = extract_intelligence(scammer_text)  # ALWAYS extract - don't depend on scam detection
    scam_type = None

    if detection.is_scam:
        scam_type = "upi_fraud"  # Default, can be enhanced later
        new_phase = next_phase(current_phase, message)
    else:
        new_phase = current_phase

    # 4️⃣ CHECK FLAGGED INTELLIGENCE INSTANTLY (even if not detected as scam!)
    if intelligence:
        is_flagged, flag_reason = check_flagged_intelligence(
            {
                "upi_ids": intelligence.upi_ids,
                "bank_accounts": intelligence.bank_accounts,
                "phishing_links": intelligence.phishing_links
            }
        )
        
        if is_flagged:
            logger.warning(f"🚨 CONVERSATION BLOCKED - FLAGGED INTELLIGENCE: {flag_reason}")
            
            fingerprint = analyze_attacker(
                history=history,
                ip=ip or "unknown",
                user_agent=user_agent or "unknown"
            )
            risk = compute_risk_score(
                detection=detection,
                fingerprint=fingerprint,
                phase=new_phase,
                intelligence=intelligence
            )
            
            # Save blocked state
            save_conversation(
                conversation_id,
                {
                    "phase": new_phase,
                    "messages": history,
                    "blocked": True,
                    "blocked_reason": "flagged_intelligence"
                }
            )
            
            return ScamAnalysisResponse(
                is_scam=detection.is_scam,
                scam_type=scam_type,
                extracted_intelligence=intelligence,
                confidence=detection.confidence,
                honeypot_reply=flag_reason,
                risk=risk,
                blocked=True,
                blocked_message=flag_reason,
                flagged_match=True
            )

    # 5️⃣ Check if conversation should be blocked (due to length/patterns)
    should_block, blocked_msg = should_block_conversation(history, new_phase, detection.confidence)
    
    if should_block:
        # Block the conversation - don't generate LLM reply
        reply = blocked_msg or "Your account has been temporarily locked."
        fingerprint = analyze_attacker(
            history=history,
            ip=ip or "unknown",
            user_agent=user_agent or "unknown"
        )
        risk = compute_risk_score(
            detection=detection,
            fingerprint=fingerprint,
            phase=new_phase,
            intelligence=intelligence
        )
        
        # Save blocked state and return
        save_conversation(
            conversation_id,
            {
                "phase": new_phase,
                "messages": history,
                "blocked": True,
                "blocked_reason": "pattern_detected"
            }
        )
        
        return ScamAnalysisResponse(
            is_scam=detection.is_scam,
            scam_type=scam_type,
            extracted_intelligence=intelligence,
            confidence=detection.confidence,
            honeypot_reply=reply,
            risk=risk,
            blocked=True,
            blocked_message=reply,
            flagged_match=False
        )

    # 6️⃣ Generate honeypot reply (NOW USING LLM via ai_honeypot.py!)
    reply = generate_honeypot_reply(history, scam_type or "unknown", new_phase)

    # 7️⃣ Build attacker fingerprint (GUVI-safe defaults)
    fingerprint = analyze_attacker(
        history=history,
        ip=ip or "unknown",
        user_agent=user_agent or "unknown"
    )

    # 8️⃣ Risk scoring
    risk = compute_risk_score(
        detection=detection,
        fingerprint=fingerprint,
        phase=new_phase,
        intelligence=intelligence
    )

    # 9️⃣ ADD EXTRACTED INTELLIGENCE TO FLAGGED DATABASE FOR FUTURE BLOCKING
    if detection.is_scam and intelligence:
        add_flagged_intelligence(
            upi_ids=intelligence.upi_ids,
            bank_accounts=intelligence.bank_accounts,
            phishing_links=intelligence.phishing_links
        )

    # 🔟 Save honeypot reply
    history.append({
        "role": "honeypot",
        "content": reply
    })

    # 1️⃣1️⃣ Persist updated conversation
    save_conversation(
        conversation_id,
        {
            "phase": new_phase,
            "messages": history
        }
    )

    # 1️⃣2️⃣ Return API response
    return ScamAnalysisResponse(
        is_scam=detection.is_scam,
        scam_type=scam_type,
        extracted_intelligence=intelligence,
        confidence=detection.confidence,
        honeypot_reply=reply,
        risk=risk,
        blocked=False,
        blocked_message=None,
        flagged_match=False
    )