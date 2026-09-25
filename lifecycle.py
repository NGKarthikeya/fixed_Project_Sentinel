from enum import Enum

class ScamPhase(str, Enum):
    INITIAL = "initial"           # greeting / vague threat
    PRESSURE = "pressure"         # urgency, fear, warnings
    PAYMENT = "payment"           # UPI / money ask
    ESCALATION = "escalation"     # alternate methods, links
    EXIT = "exit"                 # stop replying / trap sprung