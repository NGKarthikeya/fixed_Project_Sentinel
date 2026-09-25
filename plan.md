# Project Sentinel — Email Threat Detection, GeoLocation \& Forensic Intelligence

**Plan for extending SwarmSentinel to meet the SIH Problem Statement**

\---

## 1\. Context

The current repo (`Project-Sentinel`) already ships a working dual-layer cyber resilience platform:

* **Active Honeypot** — Chrome extension, traps phishing/scams at the browser level
* **SwarmSentinel** — Pheromone Graph + multi-agent swarm (Scouts, Soldiers, Queen) for correlation, decay-based noise filtering, and sub-second autonomous containment
* **Email content analysis** — `email\\\_analyzer.py` / `intelligence.py`: NLP + Gemini LLM scam detection, phishing-link and UPI/bank-account extraction, urgency/payment/brand-spoof heuristics, risk scoring

The SIH PS asks for something adjacent but distinct: **deep forensic tracing of email origin** — headers, SPF/DKIM/DMARC, IP geolocation, domain intelligence, sender attribution, and investigative reporting. This is a **forensics layer built on top of the existing engine**, not a rebuild.

\---

## 2\. Tech Stack

### Existing (already in `requirements.txt`)

```
fastapi>=0.138.0
starlette>=0.40,<0.49
uvicorn>=0.30
redis>=5.0
pydantic>=2.9
python-dotenv>=1.0
pytest>=8.0
pytest-asyncio>=0.23
httpx>=0.27
google-generativeai>=0.7.2
networkx>=3.1
websockets>=12.0
numpy>=1.24.0
scipy>=1.10.0
```

### New dependencies to add for this feature set

```
dkimpy            # DKIM signature verification
pyspf             # SPF validation (or checkdmarc as an alternative)
checkdmarc        # DMARC alignment checking
geoip2            # IP -> geolocation lookups (MaxMind GeoLite2 database)
python-whois      # Domain registration / registrar intelligence
dnspython         # MX / SPF / DMARC DNS record lookups
rapidfuzz         # Domain lookalike / brand-spoof edit-distance detection
weasyprint        # HTML -> PDF forensic report rendering
```

Frontend addition: **Leaflet.js** (CDN, no install) for the geolocation trace map in the dashboard.

\---

## 3\. Feature Breakdown

### 3.1 Email Header \& Protocol Analysis Module(Karthikeya)

**What it is:** Parses the raw technical structure of an email — `Received` chain, `Message-ID`, `Return-Path`, `Reply-To` — and validates SPF/DKIM/DMARC to catch spoofed or relay-manipulated mail.

**How to build it:**

* Accept the raw `.eml` (or raw header block) in the request; parse with Python's built-in `email.parser` (`BytesParser`/`Parser`)
* Extract every `Received:` header (one per hop), regex-parse each into `{from, by, with, timestamp}`, and stack them to rebuild the relay chain (earliest hop last)
* Validate auth: `dkimpy` for DKIM signatures, `pyspf`/`checkdmarc` for SPF/DMARC alignment
* Flag anomalies: out-of-order timestamps, missing expected hops, `From:` domain not matching the SPF/DKIM-authenticated domain, forged `Return-Path`

**Where it plugs in:**

* New file: `header\\\_analyzer.py` → `analyze\\\_headers(raw\\\_headers: str) -> HeaderAnalysisResult`
* Schema change: add `raw\\\_headers: Optional\\\[str]` to `EmailAnalysisRequest` in `schemas.py`
* Call from `email\\\_analyzer.py` alongside existing content analysis; merge output into `scoring.py`'s risk calculation

\---

### 3.2 Origin Traceability \& GeoLocation(Sweety)

**What it is:** Finds the real originating IP (not just the last relay) and maps it to a country/city/ISP, flagging VPN/TOR/hosting infrastructure.

**How to build it:**

* Walk the relay chain bottom-up, skip private IPs (RFC1918) and trusted MTAs (whitelist in `config.py`) — the first remaining public IP is the probable origin
* Geolocate with `geoip2` + the free **MaxMind GeoLite2** offline database (fast, no rate limits — ideal for a demo) → country, city, ISP, ASN
* Flag anonymization infrastructure: cross-check ASN/org name against known hosting-provider and TOR-exit-node lists (static list is fine for a hackathon; AbuseIPDB free tier adds live reputation scoring)

**Where it plugs in:**

* New file: `geo\\\_intel.py` → `resolve\\\_origin(relay\\\_chain) -> OriginTrace`
* New schema: `OriginTrace` (ip, country, city, isp, asn, is\_vpn, is\_tor, is\_hosting, confidence)

\---

### 3.3 Domain Intelligence(Ojas)

**What it is:** Investigates the sender's domain — registration age, registrar, and whether it's a lookalike of a real brand.

**How to build it:**

* `python-whois` → registration date (a domain registered days ago sending "your bank" emails is a major signal), registrar
* `dnspython` → MX, SPF (TXT), DMARC (TXT) records; compare the domain's claimed MX against the IP that actually sent the mail — a mismatch is a red flag
* Lookalike detection: `rapidfuzz` (edit-distance) comparing the domain against a small watchlist of real brand domains (banks, gov portals) — catches things like `sbi-verify.xyz` vs `sbi.co.in`

**Where it plugs in:**

* New file: `domain\\\_intel.py` → `analyze\\\_domain(domain) -> DomainIntelResult`
* Cache results (the same domain recurs across many emails) — reuse the caching pattern already in `storage.py`

\---

### 3.4 Sender / Infrastructure Attribution Graph(Karthikeya)

**What it is:** The cheapest, highest-leverage build — feeds every extracted indicator (sending IP, domain, ASN, UPI ID, reply-to) into the **existing Pheromone Graph**, so infrastructure reused across multiple phishing emails naturally lights up as a persistent, reinforced threat. No new engine required.

**How to build it:**

* Add new `entity\\\_type` values to `PheromoneNode`: `"email\\\_domain"`, `"email\\\_ip"`, `"asn"`, `"upi\\\_id"`
* For every analyzed email, emit a `TelemetryEvent` per indicator through the existing `POST /telemetry` pipeline
* Add edges between all indicators found in the *same* email (`signal\\\_types=\\\["email\\\_campaign"]`) — lets the graph cluster a whole campaign, not just a single message
* Scouts/Soldiers/Queen already handle decay, correlation, and incident declaration — this is pure wiring into `swarm\\\_graph.py` / `graph\\\_backend.py`

\---

### 3.5 Geolocation Trace Map (Dashboard)- (Sweety)

**What it is:** Visualizes the relay path and campaign clusters on a map, alongside the existing graph view.

**How to build it:**

* Frontend: `Leaflet.js` (CDN, lightweight) — plot each relay hop's coordinates from `OriginTrace`
* Backend: new endpoint `GET /emails/{id}/trace` returning ordered hops + coordinates
* Push live updates over the existing WebSocket with a new `msg\\\_type: "email\\\_trace"`

\---

### 3.6 Forensic Report Generator(Ojas)

**What it is:** A structured, exportable per-email report (fraud score, spoofing indicators, relay path, geo, domain intel, attribution snippet) suitable for legal/institutional handoff, with chain-of-custody.

**How to build it:**

* `weasyprint` (HTML → PDF) — template the report as HTML/CSS, render to PDF
* At ingestion, compute a SHA-256 hash of the raw `.eml` and store it immutably alongside the case — this is the chain-of-custody proof (who pulled it, when, unaltered-since-capture)
* New file: `forensic\\\_report.py` → `generate\\\_report(email\\\_id) -> bytes`
* New endpoint: `GET /emails/{id}/report`

\---

### 3.7 Privacy, Legal \& Compliance Safeguards (Ayushman)

**What it is:** Controls how long sensitive data is kept and who can see it unmasked.

**How to build it:**

* Config-driven retention window in `config.py` + a scheduled cleanup job that purges raw email bodies after N days while keeping hashes/indicators for evidentiary continuity
* Field-level masking (e.g. bank account → last 4 digits only) applied at *render* time in dashboard/reports, not at storage time — so an authorized investigator can still "unmask," with that action logged
* New file: `privacy.py` → `mask\\\_field()`, `apply\\\_retention\\\_policy()`

\---

## 4\. What's Already There (no rework needed)

|Component|File(s)|Reused for|
|-|-|-|
|Content-based scam/phishing detection|`email\\\_analyzer.py`, `intelligence.py`|Feeds into combined risk score alongside new forensic signals|
|Risk scoring \& scam-phase tracking|`scoring.py`, `lifecycle.py`|Extended to weight header/geo/domain signals|
|Pheromone Graph correlation engine|`swarm\\\_graph.py`, `graph\\\_backend.py`, `correlation.py`|Attribution graph (3.4) wired directly into this|
|MITRE ATT\&CK mapping schema|`MitreMatch`, `AttackChain` in `schemas.py`|Campaign/technique labeling for forensic reports|
|Autonomous containment \& playbooks|`containment.py`, `policy.py`|Can add email-specific actions (quarantine, alert)|
|Real-time dashboard + WebSocket alerts|`dashboard/`, `WSMessage`|Extended with trace map (3.5)|
|FastAPI ingestion pipeline|`ingestion.py`, `event\\\_queue.py`|Unchanged; new modules plug into it|

## 5\. What Needs Modification(Ayushman)

* `EmailAnalysisRequest` (`schemas.py`) — add `raw\\\_headers`/`raw\\\_eml`, `sender\\\_ip`, SPF/DKIM/DMARC result fields
* `email\\\_analyzer.py` — call new header/geo/domain modules, merge their signals into the existing pipeline
* `scoring.py` — weight header-anomaly, geo, and domain-reputation signals, not just content cues
* Brand-spoof detection — currently keyword+regex on display name only; needs real domain-lookalike + auth-failure logic
* Dashboard — extend the existing graph view with a geolocation map and trace-path panel

\---

## 6\. Suggested Build Order

1. **Header analysis + SPF/DKIM/DMARC** — the PS's core ask
2. **Geo/IP origin tracing** — pairs directly with #1, high demo impact
3. **Attribution graph wiring** — cheapest, reuses \~90% of existing code
4. **Domain intelligence** — strong signal, moderate effort
5. **Dashboard trace map** — visual payoff for judges
6. **Forensic report export** — closes the loop on "investigation workflow"
7. **Privacy/retention layer** — build last, but state it explicitly in the pitch — judges specifically listed it as an expected safeguard

