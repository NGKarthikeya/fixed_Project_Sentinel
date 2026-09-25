from lifecycle import ScamPhase

def honeypot_reply_for_phase(phase: ScamPhase) -> str:
    if phase == ScamPhase.INITIAL:
        return "Hello, I got your message. What is this about?"

    if phase == ScamPhase.PRESSURE:
        return "I’m a bit worried. Can you explain what will happen?"

    if phase == ScamPhase.PAYMENT:
        return "It’s not going through. Can you confirm the UPI again?"

    if phase == ScamPhase.ESCALATION:
        return "This is still failing. Do you have an official link?"

    if phase == ScamPhase.EXIT:
        return "Okay, I will check and get back to you."

    return "Please explain."