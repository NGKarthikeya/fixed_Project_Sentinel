# SwarmSentinel: AI-Driven Cyber Resilience

> [!IMPORTANT]
> **HACKATHON JUDGES:** Please see our [Final Evidence Pack](file:///C:/Users/Ayush/OneDrive/Desktop/HONEY_POT/JUDGE_EVIDENCE_PACK.md) for architecture diagrams, performance metrics, and security guarantees.

SwarmSentinel is a next-generation AI-driven honeypot and threat intelligence platform. Built on the principles of swarm intelligence and pheromone graph theory, it detects, correlates, and contains distributed attacks at sub-second speeds.

---

## 📊 Live Performance Dashboard

*Note: These metrics are generated dynamically by our live benchmark suite (`demo/run_scenarios.py`) running against the asynchronous ingestion pipeline.*

| Key Performance Indicator | Current Value | Target Standard |
| :--- | :--- | :--- |
| **Detection Rate** | 100% | > 95% |
| **False Positive Rate** | 0.0% | < 5% |
| **Mean Time To Detect (MTTD)** | **~508ms** | < 5 seconds |
| **Mean Time To Respond (MTTR)** | **~718ms** | < 1 minute |

> [!TIP]
> **Sub-millisecond Scale:** Our non-blocking HTTP ingestion absorbs telemetry with a p99 enqueue latency of **0.06ms**, meaning zero dropped events during massive botnet surges.

---

## 🎯 The Problem
Modern Security Operations Centers (SOCs) are drowning in alert fatigue. Disconnected signals from firewalls, IDPs, and endpoint sensors are reviewed in isolation, allowing attackers to persist and move laterally while analysts manually piece together the narrative. Traditional SIEMs are too slow, and manual playbooks mean containment happens hours after the breach.

## 🚀 The Differentiated Approach
We don't use static SIEM rules. SwarmSentinel utilizes a **Pheromone Graph**:
- **Continuous Decay:** Anomalies naturally "decay" over time. Only coordinated, persistent, or rapidly escalating threats leave enough "pheromone" to trigger an incident.
- **Auto-Correlation:** A single user clicking a phishing link, failing a login, and a related IP scanning a port instantly form a highly connected graph. 
- **Autonomous Playbooks:** When the graph crosses critical risk thresholds, SwarmSentinel calculates the exact blast radius and fires automated containment playbooks instantly.

## 💼 Quantified Impact (Buyer Value)

### For the SOC Lead
- **Zero Alert Fatigue:** Instead of 10,000 isolated alerts, the SOC receives 5 high-fidelity "Incidents" backed by correlated graph evidence.
- **Instant Containment:** Autonomous playbook execution drops MTTR from hours to under 1 second.
- **Actionable Context:** Every incident natively predicts the attacker's next steps mapped to the MITRE ATT&CK framework.

### For the Engineering Lead
- **Deterministic Scale:** Max node/edge graph caps and strict O(1) eviction guarantees stable memory footprint under infinite load.
- **Microservice Ready:** A decoupled FastAPI backend with an asynchronous queue that can easily scale horizontally over Redis/Kafka.

---

## 🗺️ Demo Scenarios & Outcomes

Below is a map of the live scenarios we test against, demonstrating the platform's multi-layered detection.

### 1. Phishing Mesh Attack
- **Trigger:** Simultaneous phishing clicks from `victim1@corp.local` and traffic to `verify-wallet-support.com`.
- **Detection Result:** ✅ Detected (0.56s MTTD)
- **Containment:** Blocked malicious IP for 90 minutes.
- **Risk Reduction:** Prevented external C2 communication and initial credential theft.

### 2. Account Takeover (Credential Pressure)
- **Trigger:** Impossible travel session overlapping with password reuse across login prompts for `alice@corp.local`.
- **Detection Result:** ✅ Detected (0.48s MTTD)
- **Containment:** Instant session revocation and user notification.
- **Risk Reduction:** Stopped lateral movement from a hijacked corporate identity before any internal resources were accessed.

### 3. Payment Fraud Escalation
- **Trigger:** High-risk financial anomalies (unrecognized UPI / Bank accounts) reported by the Honeypot and FinOps sensors.
- **Detection Result:** ✅ Detected (0.48s MTTD)
- **Containment:** Forensic disk snapshot triggered.
- **Risk Reduction:** Secured immutable forensic evidence required for legal / compliance recovery while freezing the transaction path.

### 4. Benign Baseline
- **Trigger:** Normal corporate chatter, single successful logins.
- **Detection Result:** ✅ Ignored (0% False Positives).
- **Risk Reduction:** Prevents the SOC from chasing ghosts and disrupting business continuity.

---

## 🛠️ Deployment Simplicity

SwarmSentinel runs out-of-the-box with zero external dependencies required for the local prototype. 

### Developer Setup

Use a project-local virtual environment for all installs:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

### Start/Stop the Server

Use the single PowerShell switcher to manage the local server:

```powershell
.\scripts\ServerSwitch.ps1 toggle
```

Other supported actions:

```powershell
.\scripts\ServerSwitch.ps1 start
.\scripts\ServerSwitch.ps1 stop
.\scripts\ServerSwitch.ps1 status
```

The switcher uses the local `.venv` and writes runtime state into `.run/`.

### Generate the KPI Dashboard

Run the local demo harness and re-calculate the live metrics (outputs to `demo/results/latest_metrics.json`):

```powershell
$env:PYTHONPATH="."; .\.venv\Scripts\python.exe demo\run_scenarios.py
```

### API Overview

- `POST /honeypot` - Inject honeypot telemetry
- `POST /telemetry` - Async telemetry pipeline
- `GET /incidents` - Query correlated threats
- `GET /playbooks` - Fetch available containment actions
- `POST /incidents/{incident_id}/action` - Trigger containment

*For more details, see the [Documentation Index](docs/README.md).*
