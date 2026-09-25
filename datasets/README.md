# Bundled Security Datasets — Project Sentinel

All four files in this directory are **curated offline snapshots** derived from
public security research datasets. The app works completely offline — no
internet access, API keys, or Kaggle account required.

---

## File Map

| File | Source Inspiration | Scenario | Redis Key(s) Seeded |
|---|---|---|---|
| `phishing_c2_cic_ids.csv` | CIC-IDS2017 / CSE-CIC-IDS2018 (UNB) | S1 Phishing Mesh & C2 Traffic | `flagged:phishing_links`, `pheromone:ip:*` |
| `account_takeover_secrepo.csv` | SecRepo SSH / RADIUS Auth Logs | S2 Account Takeover & Impossible Travel | `pheromone:user:*`, `pheromone:ip:*` |
| `payment_fraud_unsw_nb15.csv` | UNSW-NB15 (Univ. of New South Wales) | S3 Payment Fraud Escalation | `flagged:upi_ids`, `pheromone:ip:*` |
| `benign_baseline_cert.json` | CERT Insider Threat Test Dataset (CMU) | S4 Benign Baseline / False Positive Testing | `_detector_state` ZScore warm-up (in-memory) |

---

## Why These Datasets?

### S1 — `phishing_c2_cic_ids.csv` (CIC-IDS2017 / CSE-CIC-IDS2018)
- Original source: University of New Brunswick (UNB) Canadian Institute for Cybersecurity
- Contains labelled network flow data covering Botnet-ARES, Web-Attack-XSS, Web-Attack-SQLi,
  DoS-Hulk, DoS-GoldenEye, PortScan, Brute-Force, and Infiltration attack categories.
- This snapshot extracts: **attacker source IPs** → seeded as `pheromone:ip:*` and
  **malicious C2 domains** (verify-wallet-support.com style) → seeded into `flagged:phishing_links`.
- Full dataset: https://www.unb.ca/cic/datasets/ids-2017.html

### S2 — `account_takeover_secrepo.csv` (SecRepo)
- Original source: https://secrepo.com — free public security log samples
- Contains SSH/RADIUS authentication logs with: username, source IP, country, city,
  lat/lon (geo), success/failure result, and failure reason.
- This snapshot simulates **impossible travel** (login from Mumbai then Tokyo 10 min later)
  and **credential stuffing** patterns matching `alice@corp.local` and other USERS in
  `telemetry_simulator.py`.
- Seeded as: per-user pheromones (score ∝ failure count) and per-IP pheromones.

### S3 — `payment_fraud_unsw_nb15.csv` (UNSW-NB15)
- Original source: UNSW Canberra Cyber (research.unsw.edu.au/projects/unsw-nb15-dataset)
- **No Kaggle account required** — available directly from the university.
- Contains network flow records with attack categories: Exploits, Fuzzers, DoS,
  Reconnaissance, Backdoors, Analysis, Shellcode, Worms.
- Each attack row has a `financial_proxy_id` (TXN-CIC-XXXXX) that maps to the
  `flagged:upi_ids` Redis set, simulating fraudulent transaction IDs.
- High-risk source IPs (score ≥ 80) are also seeded as pheromones.

### S4 — `benign_baseline_cert.json` (CERT Insider Threat)
- Original source: Carnegie Mellon University CERT Division
  (resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099)
- Provides months of background user activity for normal corporate users.
- This snapshot covers all 8 `corp.local` users across login, file_access, email,
  http_browse, device_connect, and logout activities with realistic low scores (3–12).
- Loaded into `detectors._detector_state` to pre-warm the `ZScoreDetector`
  history so the first real attack event immediately produces a meaningful z-score
  rather than "Insufficient history (0/3 samples)".

---

## Extending with Full Datasets

To use the full research datasets instead of these snapshots, download them from
the sources above and place the files in this directory with the same column
format, then restart the server. The seeder auto-reads from these paths:

```
datasets/phishing_c2_cic_ids.csv
datasets/account_takeover_secrepo.csv
datasets/payment_fraud_unsw_nb15.csv
datasets/benign_baseline_cert.json
```

To disable seeding entirely (e.g. in CI):
```env
DATASET_SEED_ON_STARTUP=false
```

---

## Why Not Kaggle?

The IEEE-CIS Fraud Detection and Credit Card Fraud datasets on Kaggle require
a Kaggle account and CLI credentials to download. Kaggle is a good **future**
option for expanding the payment fraud scenario — the column mapping for IEEE-CIS
is pre-planned in `dataset_seeder.py::_seed_payment_fraud()`. For now, UNSW-NB15
provides equivalent functionality without any account requirements.
