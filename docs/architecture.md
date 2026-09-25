# Agentic Honeypot Backend Architecture

## 1. Current Folder Structure

```
HONEY_POT/
├── main.py                # FastAPI entry point
├── controller.py          # Orchestrates detection, scoring, and replies
├── intelligence.py        # Scam detection + intelligence extraction
├── lifecycle.py           # Scam phase enum
├── phase_engine.py        # Phase transition logic
├── honeypot_brain.py      # Rule-based honeypot reply generator
├── ai_honeypot.py         # Alternate reply generator (rule-based for now)
├── fingerprint.py         # Attacker fingerprinting logic
├── scoring.py             # Risk scoring
├── storage.py             # Conversation persistence (Redis)
├── schemas.py             # Pydantic request/response models
├── utils.py               # Reserved for helpers (currently empty)
└── ARCHITECTURE.md        # This document
```

---

## 2. File Purpose (One Sentence Each)

| File | Purpose |
|------|---------|
| `main.py` | Initializes FastAPI app and exposes the `/honeypot` endpoint. |
| `controller.py` | Central workflow: detection, phase update, reply, fingerprint, scoring, persistence. |
| `intelligence.py` | Detects scams and extracts simple indicators like UPI IDs and links. |
| `lifecycle.py` | Defines `ScamPhase` states. |
| `phase_engine.py` | Determines next `ScamPhase` from message content. |
| `honeypot_brain.py` | Generates canned replies by phase. |
| `ai_honeypot.py` | Alternate reply generator (rule-based placeholder for future AI). |
| `fingerprint.py` | Builds attacker fingerprint signals from conversation history. |
| `scoring.py` | Produces risk score and level. |
| `storage.py` | Stores and retrieves conversation state from Redis. |
| `schemas.py` | Pydantic models for request and response payloads. |
| `utils.py` | Utility helpers (currently unused). |

---

## 3. Data Flow

```
Client Request (JSON)
        ↓
    main.py (/honeypot)
        ↓
    controller.py
        ↓
  ┌──────────────────────────────┐
  │ detect_scam() (intelligence) │
  │ next_phase() (phase_engine)  │
  │ honeypot_reply_for_phase()   │
  │ analyze_attacker()           │
  │ compute_risk_score()         │
  └──────────────────────────────┘
        ↓
    storage.py (save state)
        ↓
    Response (ScamAnalysisResponse)
```

---

## 4. Key Design Principles

✅ **Single Responsibility**: each module handles one concern.

✅ **Separation of Concerns**:
- API in `main.py`
- Workflow in `controller.py`
- Domain logic split across detection, phase, scoring, fingerprint

✅ **Extensible**: `ai_honeypot.py` can swap to a model-based generator without changing the API.