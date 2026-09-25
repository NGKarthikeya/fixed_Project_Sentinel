# fingerprint.py
from datetime import datetime

def analyze_attacker(history: list, ip: str, user_agent: str) -> dict:
    scammer_messages = [m for m in history if m["role"] == "scammer"]

    pressure_words = ["urgent", "fast", "now", "immediately", "today"]
    pressure = any(
        any(word in m["content"].lower() for word in pressure_words)
        for m in scammer_messages
    )
    
    links = any("http" in m["content"].lower() for m in scammer_messages)

    payment_words = ["upi", "pay", "payment", "transfer", "bank", "account", "₹"]
    payment_intent = any(
        any(word in m["content"].lower() for word in payment_words)
        for m in scammer_messages
    )

    message_count = len(scammer_messages)

    return {
        "ip": ip,
        "user_agent": user_agent,
        "pressure_language": pressure,
        "links_shared": links,
        "payment_intent": payment_intent,
        "message_count": message_count
    }