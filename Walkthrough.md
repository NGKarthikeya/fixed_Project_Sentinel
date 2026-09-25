# SwarmSentinel: Technical Walkthrough & Architecture Document

## 1. Project Overview & Vision
**What is SwarmSentinel?**
SwarmSentinel is a next-generation, AI-driven Cyber Resilience platform designed specifically to protect Critical National Infrastructure. Inspired by biological swarm intelligence, it acts as an autonomous "immune system" for government and enterprise networks, capable of detecting behavioural anomalies and orchestrating automated incident response at sub-second speeds.

**The Problem Statement & Context**
Critical national infrastructure has become a primary target for sophisticated cyber actors. India's public institutions are under immense pressure; CERT-In reported handling over 1.59 million cybersecurity incidents in 2023, with the numbers climbing through 2024-2025. Recent high-profile attacks underscore this crisis:
- **AIIMS Delhi (2022)** was paralysed for over two weeks by ransomware.
- **CBSE (2024 & 2026)** suffered catastrophic data breaches and coordinated cyberattacks ahead of board exams, forcing emergency shutdowns.

With over 70% of government entities operating on end-of-life IT infrastructure, attackers do not have to work hard to find entry points. The true failure is **detection speed**. Most public sector organisations discover breaches weeks or months after infiltration. Advanced Persistent Threats (APTs) operate "low-and-slow" to evade traditional signature-based detection. 

**Our Solution**
SwarmSentinel introduces a **behavioural intelligence layer**. Instead of relying on known malware signatures (which are useless against zero-day APTs), it builds behavioural profiles and correlates weak signals across heterogeneous IT environments. By mapping attack progressions against the MITRE ATT&CK framework and orchestrating automated containment, SwarmSentinel compresses the time from initial compromise to detection and response from **weeks to milliseconds**.

---

## 2. Alignment with Challenge Deliverables
Our platform specifically addresses the core pillars of the challenge statement:

1. **Behavioural Anomaly Detection Engine:** We replaced static SIEM rules with a dynamic **Pheromone Graph**. Our system continuously scores deviations in telemetry (log data, endpoint sensors) without relying on known signatures.
2. **APT Campaign Attribution Agent:** We integrated Google Gemini as a highly capable AI agent trained to map observed graph clusters directly to the **MITRE ATT&CK framework**, predicting likely next-stage moves and recommending defensive actions.
3. **Autonomous Incident Response Orchestrator (SOAR):** SwarmSentinel executes pre-approved containment playbooks instantly (e.g., isolate endpoint, revoke credential, block IP, VM snapshot) the moment high-confidence threats are confirmed, incorporating defined blast radius thresholds for safety.

---

## 3. How the Pheromone Graph Works (A Beginner's Guide)
To a first-time user, the graph visualization on the dashboard might look like a complex web of dots and lines. Here is exactly what you are looking at:

- **Nodes (The Dots):** Each dot represents an "Entity" in the network (e.g., an IP address, a User email, or a Host machine).
- **Edges (The Lines):** The lines represent interactions (e.g., a User logging into a Server, or an IP sending a payload).
- **Pheromones (The Colors/Weight):** Just like real ants leave chemical trails, our sensors deposit digital "pheromones" on nodes/edges when suspicious behaviour occurs. The thicker and brighter the line, the higher the pheromone concentration, indicating a higher probability of malicious activity.
- **The Multi-Agent Swarm (Agentic AI):** 
  - **Scouts** wander the graph looking for tiny anomalies (weak signals).
  - **Soldiers** swarm to areas with high pheromone concentrations to build the attack corridor (lateral movement detection).
  - **The Queen** observes the entire graph to declare a coordinated incident.
- **Decay:** Over time, pheromones evaporate. If an event was a false positive, it simply fades away, keeping the graph clean and eliminating alert fatigue.

---

## 4. Technology Stack & Architecture

| Technology / Pattern | Role & Why We Chose It |
| :--- | :--- |
| **Agentic AI / Multi-Agent Systems** | We built a custom Ant Colony Optimization (ACO) algorithm with three distinct agent types (`Scout`, `Soldier`, `Queen`) to autonomously patrol the network. |
| **Graph AI (NetworkX)** | The mathematical engine powering our attack path analysis and lateral movement detection. |
| **Google Gemini LLM** | Acts as the Knowledge Graph and RAG layer. Gemini analyzes the pheromone clusters and maps the TTPs directly to the MITRE ATT&CK framework. |
| **Python & FastAPI** | Acts as the core backend. Chosen for its extreme speed and native `asyncio` support, allowing us to ingest high-volume telemetry without crashing. |
| **Vanilla JS & HTML/CSS** | Powers the dynamic dashboard. We avoided heavy frameworks to ensure the dashboard remains incredibly lightweight and fast. |
| **Chrome Extension APIs** | Used for the Honeypot sensor and active containment interface. It allows the platform to live directly in the browser where users operate. |

---

## 5. Hackathon Transparency & Benchmark Data
To maintain complete transparency for the hackathon evaluation: **SwarmSentinel utilizes a robust, pre-defined simulation dataset.** 

**Why did we do this?**
Due to the strict time constraints of a hackathon, waiting for a sophisticated APT to infiltrate live infrastructure is unfeasible. To rigorously evaluate our anomaly detection rate, false positive rate, and MTTD/MTTR improvement, we built a `TelemetrySimulator`. 

This simulator dynamically generates highly realistic, structured telemetry for complex scenarios (like Phishing, Account Takeovers, and Payment Fraud) and pushes them through our live async queue just as a real sensor would. This guarantees full auditability of every automated action taken during the demo and ensures consistent, verifiable results.

---

## 6. Current Progress & Dual-Platform Capability
As the project evolved, it naturally split into two incredibly powerful, standalone capabilities that communicate seamlessly:

1. **The SwarmSentinel Backend:** The core graph AI engine, multi-agent orchestrator, and SIEM/SOAR platform.
2. **The Active Honeypot (Chrome Extension):** Currently, our Chrome extension actively scans and identifies potential scams, phishing links, and fraud emails directly within the user's browser. It acts as the primary frontline sensor feeding behavioural data into the Swarm.

These can operate entirely independently, but they are most powerful when combined to form a holistic Cyber Resilience platform.

---

## 7. Future Scope & Roadmap

As we look beyond the hackathon to deploy this across actual government infrastructure, we have a clear roadmap:

- **WhatsApp Threat Integration:** We plan to expand the Honeypot sensor beyond browser emails to monitor WhatsApp Web, capturing the massive rise in SMS/WhatsApp-based phishing (Smishing) that targets public sector employees.
- **Integration with Real Enterprise Honeypots:** We will replace our `TelemetrySimulator` with live data feeds from industry-standard honeypots like **Cowrie** (SSH/Telnet), **Dionaea** (malware capturing), and the broader **T-Pot Platform**. This will allow SwarmSentinel to ingest live, wild attacks from the internet in real-time.
- **Cyber Resilience Digital Twin:** Expanding our simulation capabilities so government agencies can run attack path modelling and Red Team scenarios against a virtual twin of their architecture without touching live production systems.
- **Horizontal Scaling:** Transitioning our in-memory `asyncio` queue to a distributed message broker like Apache Kafka, allowing the Swarm to monitor massive, multi-national IT/OT environments seamlessly.
