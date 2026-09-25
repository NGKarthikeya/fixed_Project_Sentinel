from lifecycle import ScamPhase

def next_phase(current: ScamPhase, message: str) -> ScamPhase:
    msg = message.lower()

    if current == ScamPhase.INITIAL:
        if "urgent" in msg or "blocked" in msg:
            return ScamPhase.PRESSURE

    if current == ScamPhase.PRESSURE:
        if "upi" in msg or "pay" in msg or "₹" in msg:
            return ScamPhase.PAYMENT

    if current == ScamPhase.PAYMENT:
        if "link" in msg or "http" in msg or "bank" in msg:
            return ScamPhase.ESCALATION

    if current == ScamPhase.ESCALATION:
        return ScamPhase.EXIT

    return current