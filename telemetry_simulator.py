"""
Telemetry Event Simulator for Honeypot Demo Scenarios.

Generates realistic-looking network security events that simulate various
attack patterns against an Indian government/corporate network environment.
Every event conforms to the TelemetryEvent schema::

    {
        "entity_type": str,   # "ip", "user", "host", "domain", "conversation"
        "entity_id": str,     # unique identifier
        "score": float,       # 0-100 risk score
        "evidence": [         # list of evidence dicts
            {"type": str, "text": str, "source": str}
        ],
        "ts": float           # unix timestamp
    }

Usage::

    from telemetry_simulator import TelemetrySimulator

    sim = TelemetrySimulator()
    events = sim.generate_apt_killchain()
    for e in events:
        print(e["entity_type"], e["entity_id"], e["score"])
"""

import time
import random
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Type alias for a single telemetry event dict.
TelemetryEvent = Dict[str, Any]


class TelemetrySimulator:
    """Generates realistic telemetry events for honeypot demo scenarios.

    Pre-populates pools of internal IPs, external (attacker) IPs, users,
    hosts, and malicious domains drawn from an Indian gov/corporate context.
    Each ``generate_*`` method returns a ``list[TelemetryEvent]`` with
    monotonically-increasing timestamps spaced a few seconds apart so the
    sequence looks natural when played back.
    """

    # ------------------------------------------------------------------
    # Entity pools
    # ------------------------------------------------------------------
    INTERNAL_IPS: List[str] = [
        "10.20.1.10",
        "10.20.1.25",
        "10.20.2.30",
        "10.20.2.45",
        "10.20.3.50",
        "10.20.3.60",
        "10.20.4.15",
        "10.20.4.80",
        "10.20.5.12",
        "10.20.5.99",
    ]

    ATTACKER_IPS: List[str] = [
        "185.220.101.34",
        "185.220.102.8",
        "185.143.223.75",
        "91.219.236.90",
        "91.234.99.42",
        "91.240.118.15",
        "185.56.80.101",
        "91.192.100.55",
    ]

    USERS: List[str] = [
        "alice@corp.local",
        "bob@corp.local",
        "admin@corp.local",
        "priya.sharma@corp.local",
        "rahul.mehta@corp.local",
        "neha.gupta@corp.local",
        "vikram.singh@corp.local",
        "svc-backup@corp.local",
    ]

    HOSTS: List[str] = [
        "ws-finance-01",
        "ws-finance-02",
        "ws-hr-01",
        "srv-dc-01",
        "srv-dc-02",
        "srv-file-01",
        "srv-web-01",
        "srv-mail-01",
        "srv-db-01",
        "srv-app-01",
    ]

    MALICIOUS_DOMAINS: List[str] = [
        "verify-bank-login.com",
        "secure-update-portal.net",
        "gov-epayment-verify.in",
        "nic-logins-secure.org",
        "corp-vpn-update.net",
        "mail-auth-check.com",
    ]

    BENIGN_DOMAINS: List[str] = [
        "google.com",
        "microsoft.com",
        "github.com",
        "stackoverflow.com",
        "nic.in",
        "india.gov.in",
    ]

    SCAN_PORTS: List[int] = [22, 80, 443, 3389, 8080, 8443, 445, 1433, 3306, 5432]

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        self._base_ts: float = time.time()
        logger.info("TelemetrySimulator initialised – base ts %.2f", self._base_ts)

    def _event(
        self,
        entity_type: str,
        entity_id: str,
        score: float,
        evidence: List[Dict[str, str]],
        ts: float,
    ) -> TelemetryEvent:
        """Build a single TelemetryEvent dict."""
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "score": round(score, 2),
            "evidence": evidence,
            "ts": round(ts, 3),
        }

    def _evidence(self, etype: str, text: str, source: str) -> Dict[str, str]:
        """Build a single evidence dict."""
        return {"type": etype, "text": text, "source": source}

    def _jitter(self, base: float, lo: float = 1.0, hi: float = 5.0) -> float:
        """Return *base* advanced by a random interval in [lo, hi] seconds."""
        return base + random.uniform(lo, hi)

    def _pick(self, pool: List[str]) -> str:
        """Pick a random element from *pool*."""
        return random.choice(pool)

    # ------------------------------------------------------------------
    # Scenario generators
    # ------------------------------------------------------------------

    def generate_normal_traffic(self, num_events: int = 20) -> List[TelemetryEvent]:
        """Generate baseline benign events: logins, DNS queries, file access.

        Scores stay in the 5-25 range.  Timestamps are spread across
        realistic working hours (09:00 – 18:00 IST).

        Parameters
        ----------
        num_events:
            Number of benign events to create (default 20).

        Returns
        -------
        list[TelemetryEvent]
        """
        events: List[TelemetryEvent] = []
        ts = self._base_ts

        normal_templates = [
            lambda: (
                "user",
                self._pick(self.USERS),
                random.uniform(5, 15),
                [self._evidence("login", "Successful login from internal workstation", "auth-log")],
            ),
            lambda: (
                "ip",
                self._pick(self.INTERNAL_IPS),
                random.uniform(5, 10),
                [self._evidence("dns_query", f"DNS lookup: {self._pick(self.BENIGN_DOMAINS)}", "dns-log")],
            ),
            lambda: (
                "host",
                self._pick(self.HOSTS),
                random.uniform(8, 20),
                [self._evidence("file_access", "Read access to shared drive \\\\srv-file-01\\reports", "file-audit")],
            ),
            lambda: (
                "user",
                self._pick(self.USERS),
                random.uniform(5, 25),
                [self._evidence("email", "Sent email to external recipient (routine)", "mail-log")],
            ),
            lambda: (
                "host",
                self._pick(self.HOSTS),
                random.uniform(5, 12),
                [self._evidence("process", "Scheduled backup job executed", "sysmon")],
            ),
            lambda: (
                "ip",
                self._pick(self.INTERNAL_IPS),
                random.uniform(5, 15),
                [self._evidence("http_request", f"GET https://{self._pick(self.BENIGN_DOMAINS)}/", "proxy-log")],
            ),
        ]

        for _ in range(num_events):
            entity_type, entity_id, score, evidence = random.choice(normal_templates)()
            ts = self._jitter(ts, 2.0, 8.0)
            events.append(self._event(entity_type, entity_id, score, evidence, ts))

        logger.info("Generated %d normal-traffic events", len(events))
        return events

    def generate_port_scan(self, source_ip: Optional[str] = None) -> List[TelemetryEvent]:
        """Simulate a port-scan from a single external IP.

        Produces 5-8 sequential SYN-probe events against different ports
        with scores escalating from 30 → 70.

        Parameters
        ----------
        source_ip:
            Attacker IP to use.  Defaults to a random attacker IP.

        Returns
        -------
        list[TelemetryEvent]
        """
        source = source_ip or self._pick(self.ATTACKER_IPS)
        target_host = self._pick(self.HOSTS)
        ports = random.sample(self.SCAN_PORTS, k=random.randint(5, 8))
        scores = [30, 35, 40, 45, 50, 60, 65, 70]

        events: List[TelemetryEvent] = []
        ts = self._base_ts

        for idx, port in enumerate(ports):
            ts = self._jitter(ts, 0.5, 2.0)
            score = scores[min(idx, len(scores) - 1)]
            evidence = [
                self._evidence(
                    "port_scan",
                    f"SYN probe on port {port} targeting {target_host}",
                    "ids-alert",
                ),
            ]
            events.append(self._event("ip", source, score, evidence, ts))

        logger.info("Generated port-scan scenario (%d events) from %s", len(events), source)
        return events

    def generate_credential_stuffing(self, target_user: Optional[str] = None) -> List[TelemetryEvent]:
        """Simulate credential-stuffing against a single user account.

        Multiple failed login attempts arrive from different external IPs.
        Scores escalate: 40 → 55 → 70 → 80.

        Parameters
        ----------
        target_user:
            Account under attack.  Defaults to a random user.

        Returns
        -------
        list[TelemetryEvent]
        """
        user = target_user or self._pick(self.USERS)
        attempt_ips = random.sample(self.ATTACKER_IPS, k=min(6, len(self.ATTACKER_IPS)))
        score_ladder = [40, 48, 55, 62, 70, 80]

        events: List[TelemetryEvent] = []
        ts = self._base_ts

        for idx, ip in enumerate(attempt_ips):
            ts = self._jitter(ts, 1.0, 4.0)
            score = score_ladder[min(idx, len(score_ladder) - 1)]
            attempt_num = idx + 1
            evidence = [
                self._evidence(
                    "credential_access",
                    f"Failed login attempt #{attempt_num} from IP {ip}",
                    "auth-log",
                ),
            ]
            events.append(self._event("user", user, score, evidence, ts))

        # Final lockout event
        ts = self._jitter(ts, 0.5, 1.5)
        events.append(
            self._event(
                "user",
                user,
                85,
                [self._evidence("credential_access", "Account locked after repeated failures", "auth-log")],
                ts,
            )
        )

        logger.info("Generated credential-stuffing scenario (%d events) against %s", len(events), user)
        return events

    def generate_lateral_movement(
        self, source_ip: Optional[str] = None, hop_count: int = 3
    ) -> List[TelemetryEvent]:
        """Simulate multi-hop lateral movement inside the network.

        An attacker pivots from host to host.  Each hop creates events for
        the new host entity with evidence linking back to the prior hop.
        Scores escalate: 50 → 65 → 75 → 85.

        Parameters
        ----------
        source_ip:
            Initial compromised IP.  Defaults to a random internal IP.
        hop_count:
            Number of hops (default 3).

        Returns
        -------
        list[TelemetryEvent]
        """
        source = source_ip or self._pick(self.INTERNAL_IPS)
        available_hosts = [h for h in self.HOSTS if h not in ("srv-dc-01",)]
        hop_hosts = random.sample(available_hosts, k=min(hop_count, len(available_hosts)))
        score_ladder = [50, 65, 75, 85, 90]

        events: List[TelemetryEvent] = []
        ts = self._base_ts
        previous_entity = source

        # Initial compromise indicator
        ts = self._jitter(ts, 1.0, 3.0)
        events.append(
            self._event(
                "ip",
                source,
                45,
                [self._evidence("login_attempt", f"Suspicious RDP session from {source}", "auth-log")],
                ts,
            )
        )

        for idx, host in enumerate(hop_hosts):
            ts = self._jitter(ts, 3.0, 8.0)
            score = score_ladder[min(idx, len(score_ladder) - 1)]

            evidence = [
                self._evidence(
                    "lateral_movement",
                    f"Hop {idx + 1}: lateral move from {previous_entity} → {host} via PsExec",
                    "edr-alert",
                ),
                self._evidence(
                    "credential_access",
                    f"Pass-the-hash authentication on {host}",
                    "auth-log",
                ),
            ]
            events.append(self._event("host", host, score, evidence, ts))
            previous_entity = host

        # Attempt to reach domain controller
        ts = self._jitter(ts, 2.0, 5.0)
        events.append(
            self._event(
                "host",
                "srv-dc-01",
                90,
                [
                    self._evidence(
                        "lateral_movement",
                        f"Hop {hop_count + 1}: attempted access to domain controller srv-dc-01 from {previous_entity}",
                        "edr-alert",
                    ),
                    self._evidence(
                        "credential_access",
                        "DCSync replication request detected",
                        "dc-audit",
                    ),
                ],
                ts,
            )
        )

        logger.info("Generated lateral-movement scenario (%d events, %d hops)", len(events), hop_count)
        return events

    def generate_data_exfiltration(self, source_host: Optional[str] = None) -> List[TelemetryEvent]:
        """Simulate data exfiltration at an unusual hour (02:00 – 04:00).

        Evidence shows large outbound transfers to an external IP.
        Scores: 75-90.

        Parameters
        ----------
        source_host:
            Internal host performing the transfer.  Defaults to a random host.

        Returns
        -------
        list[TelemetryEvent]
        """
        host = source_host or self._pick(["srv-file-01", "srv-db-01", "ws-finance-01"])
        ext_ip = self._pick(self.ATTACKER_IPS)

        events: List[TelemetryEvent] = []
        ts = self._base_ts

        # Staging: large file aggregation
        ts = self._jitter(ts, 1.0, 3.0)
        events.append(
            self._event(
                "host",
                host,
                65,
                [
                    self._evidence(
                        "file_access",
                        "Bulk read of 347 files from \\\\srv-file-01\\finance\\Q4-reports",
                        "file-audit",
                    ),
                ],
                ts,
            )
        )

        # Compression
        ts = self._jitter(ts, 2.0, 5.0)
        events.append(
            self._event(
                "host",
                host,
                70,
                [
                    self._evidence(
                        "process",
                        "7z.exe compressing 2.4 GB archive at 02:17 AM IST",
                        "sysmon",
                    ),
                ],
                ts,
            )
        )

        # DNS lookup for external destination
        ts = self._jitter(ts, 1.0, 2.0)
        events.append(
            self._event(
                "ip",
                self._pick(self.INTERNAL_IPS),
                55,
                [
                    self._evidence(
                        "dns_query",
                        f"Unusual DNS lookup at 02:19 AM: drop-files-cdn.net",
                        "dns-log",
                    ),
                ],
                ts,
            )
        )

        # Exfiltration transfer
        ts = self._jitter(ts, 2.0, 4.0)
        events.append(
            self._event(
                "ip",
                ext_ip,
                85,
                [
                    self._evidence(
                        "data_transfer",
                        f"Outbound transfer of 2.4 GB to external IP {ext_ip} over HTTPS at 02:22 AM IST",
                        "netflow",
                    ),
                ],
                ts,
            )
        )

        # Post-exfil cleanup
        ts = self._jitter(ts, 1.0, 3.0)
        events.append(
            self._event(
                "host",
                host,
                90,
                [
                    self._evidence(
                        "process",
                        "Deletion of staged archive and Windows event log clearing detected",
                        "sysmon",
                    ),
                ],
                ts,
            )
        )

        logger.info("Generated data-exfiltration scenario (%d events) from %s", len(events), host)
        return events

    def generate_phishing_campaign(self) -> List[TelemetryEvent]:
        """Simulate a phishing campaign targeting multiple users.

        Several users receive similar phishing emails with links to
        malicious domains.  Scores: 55-80.

        Returns
        -------
        list[TelemetryEvent]
        """
        targets = random.sample(self.USERS, k=min(4, len(self.USERS)))
        phishing_domain = self._pick(self.MALICIOUS_DOMAINS)
        sender = f"support@{phishing_domain}"

        events: List[TelemetryEvent] = []
        ts = self._base_ts

        score_ladder = [55, 60, 65, 70]

        # Emails arriving
        for idx, user in enumerate(targets):
            ts = self._jitter(ts, 0.5, 2.0)
            score = score_ladder[min(idx, len(score_ladder) - 1)]
            events.append(
                self._event(
                    "user",
                    user,
                    score,
                    [
                        self._evidence(
                            "phishing_link",
                            f"Suspicious URL: {phishing_domain}/auth?token=a8f3e&user={user.split('@')[0]}",
                            "mail-gateway",
                        ),
                        self._evidence(
                            "email",
                            f"Phishing email from {sender}: 'Urgent: Verify your credentials'",
                            "mail-log",
                        ),
                    ],
                    ts,
                )
            )

        # One user clicks the link
        clicker = targets[0]
        ts = self._jitter(ts, 10.0, 30.0)
        events.append(
            self._event(
                "user",
                clicker,
                75,
                [
                    self._evidence(
                        "http_request",
                        f"User {clicker} visited https://{phishing_domain}/auth",
                        "proxy-log",
                    ),
                ],
                ts,
            )
        )

        # Credential harvested
        ts = self._jitter(ts, 1.0, 3.0)
        events.append(
            self._event(
                "domain",
                phishing_domain,
                80,
                [
                    self._evidence(
                        "credential_access",
                        f"POST of form data to {phishing_domain}/submit – possible credential harvest",
                        "proxy-log",
                    ),
                ],
                ts,
            )
        )

        logger.info("Generated phishing-campaign scenario (%d events)", len(events))
        return events

    def generate_apt_killchain(self) -> List[TelemetryEvent]:
        """Simulate a full APT kill-chain across multiple entities.

        Stages:
        1. Reconnaissance – external port scan
        2. Initial Access – spear-phishing email
        3. Execution – suspicious process on workstation
        4. Credential Access – credential dump on domain controller
        5. Lateral Movement – hop to file server
        6. Collection – bulk file read on file server
        7. Exfiltration – large outbound transfer to C2

        This is the flagship demo scenario.

        Returns
        -------
        list[TelemetryEvent]
        """
        attacker_ip = "185.220.101.34"
        target_user = "priya.sharma@corp.local"
        workstation = "ws-finance-01"
        dc = "srv-dc-01"
        file_server = "srv-file-01"
        c2_domain = "secure-update-portal.net"
        c2_ip = "91.219.236.90"

        events: List[TelemetryEvent] = []
        ts = self._base_ts

        # ── Stage 1: Reconnaissance ──────────────────────────────────
        recon_ports = [22, 80, 443, 3389, 8080]
        for port in recon_ports:
            ts = self._jitter(ts, 0.3, 1.0)
            events.append(
                self._event(
                    "ip",
                    attacker_ip,
                    30 + len(events) * 3,
                    [self._evidence("port_scan", f"SYN probe on port {port} from {attacker_ip}", "ids-alert")],
                    ts,
                )
            )

        # ── Stage 2: Initial Access – spear-phishing ─────────────────
        ts = self._jitter(ts, 15.0, 30.0)
        events.append(
            self._event(
                "user",
                target_user,
                55,
                [
                    self._evidence(
                        "phishing_link",
                        f"Spear-phishing email with link to https://{c2_domain}/update",
                        "mail-gateway",
                    ),
                    self._evidence(
                        "email",
                        f"From: hr-notification@{c2_domain} – 'Annual appraisal form – action required'",
                        "mail-log",
                    ),
                ],
                ts,
            )
        )

        # User clicks link
        ts = self._jitter(ts, 20.0, 60.0)
        events.append(
            self._event(
                "user",
                target_user,
                62,
                [
                    self._evidence(
                        "http_request",
                        f"User visited https://{c2_domain}/update and downloaded update.hta",
                        "proxy-log",
                    ),
                ],
                ts,
            )
        )

        # ── Stage 3: Execution ───────────────────────────────────────
        ts = self._jitter(ts, 2.0, 5.0)
        events.append(
            self._event(
                "host",
                workstation,
                68,
                [
                    self._evidence(
                        "process",
                        "mshta.exe spawned powershell.exe -enc <base64_payload>",
                        "sysmon",
                    ),
                    self._evidence(
                        "process",
                        f"Beacon callback to {c2_domain} every 60 s",
                        "edr-alert",
                    ),
                ],
                ts,
            )
        )

        # ── Stage 4: Credential Access ───────────────────────────────
        ts = self._jitter(ts, 5.0, 10.0)
        events.append(
            self._event(
                "host",
                workstation,
                72,
                [
                    self._evidence(
                        "credential_access",
                        "Mimikatz detected – sekurlsa::logonpasswords executed",
                        "edr-alert",
                    ),
                ],
                ts,
            )
        )

        ts = self._jitter(ts, 3.0, 6.0)
        events.append(
            self._event(
                "host",
                dc,
                82,
                [
                    self._evidence(
                        "credential_access",
                        "DCSync attack: replication of krbtgt hash from srv-dc-01",
                        "dc-audit",
                    ),
                    self._evidence(
                        "lateral_movement",
                        f"Admin credential used from {workstation} to authenticate to {dc}",
                        "auth-log",
                    ),
                ],
                ts,
            )
        )

        # ── Stage 5: Lateral Movement ────────────────────────────────
        ts = self._jitter(ts, 4.0, 8.0)
        events.append(
            self._event(
                "host",
                file_server,
                78,
                [
                    self._evidence(
                        "lateral_movement",
                        f"PsExec session from {dc} → {file_server} using admin@corp.local",
                        "edr-alert",
                    ),
                    self._evidence(
                        "login_attempt",
                        f"Interactive login on {file_server} via stolen golden ticket",
                        "auth-log",
                    ),
                ],
                ts,
            )
        )

        # ── Stage 6: Collection ──────────────────────────────────────
        ts = self._jitter(ts, 3.0, 6.0)
        events.append(
            self._event(
                "host",
                file_server,
                85,
                [
                    self._evidence(
                        "file_access",
                        "Bulk read: 1,247 files from \\\\srv-file-01\\classified\\defence-procurement",
                        "file-audit",
                    ),
                    self._evidence(
                        "process",
                        "rar.exe compressing 3.1 GB archive on srv-file-01",
                        "sysmon",
                    ),
                ],
                ts,
            )
        )

        # ── Stage 7: Exfiltration ────────────────────────────────────
        ts = self._jitter(ts, 2.0, 5.0)
        events.append(
            self._event(
                "ip",
                c2_ip,
                92,
                [
                    self._evidence(
                        "data_transfer",
                        f"Outbound transfer of 3.1 GB to {c2_ip} ({c2_domain}) over DNS tunnelling",
                        "netflow",
                    ),
                    self._evidence(
                        "dns_query",
                        f"High-volume TXT queries to {c2_domain} – likely DNS exfil",
                        "dns-log",
                    ),
                ],
                ts,
            )
        )

        # C2 domain entity
        ts = self._jitter(ts, 0.5, 1.5)
        events.append(
            self._event(
                "domain",
                c2_domain,
                95,
                [
                    self._evidence(
                        "threat_intel",
                        f"Domain {c2_domain} linked to APT-41 infrastructure (TI feed)",
                        "threat-intel",
                    ),
                ],
                ts,
            )
        )

        logger.info("Generated APT kill-chain scenario (%d events)", len(events))
        return events

    def generate_coordinated_attack(self) -> List[TelemetryEvent]:
        """Simulate a coordinated attack from 2-3 independent entry points.

        Multiple attacker IPs target different segments simultaneously.
        A shared C2 domain in the evidence ties them together, testing the
        swarm's ability to correlate independent signal sources.

        Returns
        -------
        list[TelemetryEvent]
        """
        c2_domain = "corp-vpn-update.net"
        attackers = random.sample(self.ATTACKER_IPS, k=3)
        entry_hosts = ["srv-web-01", "srv-mail-01", "ws-hr-01"]
        entry_users = random.sample(self.USERS, k=3)

        events: List[TelemetryEvent] = []
        ts = self._base_ts

        # ── Attacker 1: Web-app exploitation ─────────────────────────
        a1 = attackers[0]
        ts = self._jitter(ts, 1.0, 2.0)
        events.append(
            self._event(
                "ip",
                a1,
                50,
                [
                    self._evidence(
                        "exploit",
                        f"SQL injection attempt on srv-web-01 from {a1}",
                        "waf-log",
                    ),
                ],
                ts,
            )
        )

        ts = self._jitter(ts, 1.5, 3.0)
        events.append(
            self._event(
                "host",
                entry_hosts[0],
                60,
                [
                    self._evidence(
                        "process",
                        f"Web shell uploaded: /var/www/uploads/cmd.aspx from {a1}",
                        "edr-alert",
                    ),
                    self._evidence(
                        "dns_query",
                        f"Callback to {c2_domain} from {entry_hosts[0]}",
                        "dns-log",
                    ),
                ],
                ts,
            )
        )

        # ── Attacker 2: Phishing vector ──────────────────────────────
        a2 = attackers[1]
        ts = self._jitter(ts, 0.5, 2.0)
        events.append(
            self._event(
                "user",
                entry_users[1],
                55,
                [
                    self._evidence(
                        "phishing_link",
                        f"Phishing email from noreply@{c2_domain} to {entry_users[1]}",
                        "mail-gateway",
                    ),
                ],
                ts,
            )
        )

        ts = self._jitter(ts, 8.0, 15.0)
        events.append(
            self._event(
                "host",
                entry_hosts[1],
                62,
                [
                    self._evidence(
                        "process",
                        f"Macro-enabled document opened – powershell beacon to {c2_domain}",
                        "sysmon",
                    ),
                ],
                ts,
            )
        )

        # ── Attacker 3: Brute-force RDP ──────────────────────────────
        a3 = attackers[2]
        for attempt in range(1, 5):
            ts = self._jitter(ts, 0.5, 1.5)
            events.append(
                self._event(
                    "ip",
                    a3,
                    35 + attempt * 8,
                    [
                        self._evidence(
                            "credential_access",
                            f"RDP brute-force attempt #{attempt} on {entry_hosts[2]} from {a3}",
                            "auth-log",
                        ),
                    ],
                    ts,
                )
            )

        ts = self._jitter(ts, 1.0, 2.0)
        events.append(
            self._event(
                "host",
                entry_hosts[2],
                70,
                [
                    self._evidence(
                        "login_attempt",
                        f"Successful RDP login from {a3} using guessed credentials",
                        "auth-log",
                    ),
                    self._evidence(
                        "dns_query",
                        f"Beacon to {c2_domain} established from {entry_hosts[2]}",
                        "dns-log",
                    ),
                ],
                ts,
            )
        )

        # ── Correlation event: shared C2 domain ──────────────────────
        ts = self._jitter(ts, 2.0, 4.0)
        events.append(
            self._event(
                "domain",
                c2_domain,
                88,
                [
                    self._evidence(
                        "threat_intel",
                        (
                            f"C2 domain {c2_domain} contacted by 3 independent hosts: "
                            f"{', '.join(entry_hosts)} – coordinated campaign"
                        ),
                        "threat-intel",
                    ),
                ],
                ts,
            )
        )

        logger.info("Generated coordinated-attack scenario (%d events)", len(events))
        return events

    # ------------------------------------------------------------------
    # Metadata / discovery
    # ------------------------------------------------------------------

    def get_available_scenarios(self) -> List[Dict[str, Any]]:
        """Return metadata for every scenario the simulator supports.

        Each entry contains ``name``, ``description``, and
        ``event_count`` (approximate).

        Returns
        -------
        list[dict]
        """
        return [
            {
                "name": "normal_traffic",
                "description": "Baseline benign events – logins, DNS queries, file access (low scores 5-25)",
                "event_count": 20,
            },
            {
                "name": "port_scan",
                "description": "External IP sequentially probes ports 22/80/443/3389/8080 (scores 30-70)",
                "event_count": 6,
            },
            {
                "name": "credential_stuffing",
                "description": "Multiple IPs attempt credential stuffing against a single user (scores 40-85)",
                "event_count": 7,
            },
            {
                "name": "lateral_movement",
                "description": "Multi-hop lateral movement from compromised host to domain controller (scores 50-90)",
                "event_count": 5,
            },
            {
                "name": "data_exfiltration",
                "description": "Bulk file staging, compression, and 2.4 GB outbound transfer at 2 AM (scores 65-90)",
                "event_count": 5,
            },
            {
                "name": "phishing_campaign",
                "description": "Phishing emails to multiple users; one clicks and submits credentials (scores 55-80)",
                "event_count": 6,
            },
            {
                "name": "apt_killchain",
                "description": (
                    "Full APT kill-chain: recon → phishing → execution → credential theft → "
                    "lateral movement → collection → exfiltration (scores 30-95)"
                ),
                "event_count": 15,
            },
            {
                "name": "coordinated_attack",
                "description": (
                    "Three attackers hit web, mail, and RDP simultaneously; shared C2 domain "
                    "ties them together (scores 35-88)"
                ),
                "event_count": 11,
            },
        ]
