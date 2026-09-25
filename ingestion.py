"""
Log Ingestion Engine — SwarmSentinel
=====================================

Accepts real-world security log formats and converts them into
TelemetryEvents that the swarm pipeline can process.

Supported formats:
- JSON (direct TelemetryEvent schema)
- Syslog (RFC 5424 — parses severity, facility, message)
- CSV (column-mapped upload)
- CEF (Common Event Format used by ArcSight/Splunk)

This is the key business-impact addition: it proves the system can
consume real data, not just simulated events.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import time
from typing import Any, Dict, List, Optional

from api.logging_utils import logfmt

logger = logging.getLogger(__name__)

# Syslog severity → risk score mapping
SYSLOG_SEVERITY_SCORES = {
    0: 95,  # Emergency
    1: 90,  # Alert
    2: 85,  # Critical
    3: 70,  # Error
    4: 50,  # Warning
    5: 30,  # Notice
    6: 15,  # Informational
    7: 5,   # Debug
}

# CEF severity → risk score
CEF_SEVERITY_SCORES = {
    "10": 95, "9": 90, "8": 85, "7": 75, "6": 65,
    "5": 55, "4": 45, "3": 35, "2": 25, "1": 15, "0": 5,
}

# IP extraction regex
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Syslog RFC 5424 pattern
SYSLOG_PATTERN = re.compile(
    r"<(\d{1,3})>"                    # PRI
    r"(\d)?\s*"                       # VERSION (optional)
    r"(\S+)\s+"                       # TIMESTAMP
    r"(\S+)\s+"                       # HOSTNAME
    r"(\S+)\s+"                       # APP-NAME
    r"(\S+)\s+"                       # PROCID
    r"(\S+)\s*"                       # MSGID
    r"(.*)",                          # MSG
    re.DOTALL,
)

# CEF pattern
CEF_PATTERN = re.compile(
    r"CEF:(\d+)\|"                    # Version
    r"([^|]*)\|"                      # Device Vendor
    r"([^|]*)\|"                      # Device Product
    r"([^|]*)\|"                      # Device Version
    r"([^|]*)\|"                      # Signature ID
    r"([^|]*)\|"                      # Name
    r"([^|]*)\|"                      # Severity
    r"(.*)",                          # Extension
    re.DOTALL,
)


class IngestionEngine:
    """Converts raw security logs into TelemetryEvents."""

    def __init__(self) -> None:
        self._ingested_total = 0
        self._failed_total = 0
        self._sources: Dict[str, int] = {}

    def ingest_json(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Ingest a JSON event (direct TelemetryEvent format or auto-mapped).

        Accepts either the native schema or common SIEM JSON formats.
        """
        try:
            # Already in TelemetryEvent format
            if "entity_type" in data and "entity_id" in data:
                event = {
                    "entity_type": data["entity_type"],
                    "entity_id": data["entity_id"],
                    "score": float(data.get("score", 10)),
                    "evidence": data.get("evidence", []),
                    "ts": data.get("ts", time.time()),
                }
                self._record("json_native")
                return event

            # Map from common SIEM formats
            event = self._map_generic_json(data)
            if event:
                self._record("json_mapped")
            return event
        except Exception as e:
            self._failed_total += 1
            logger.error(logfmt("ingest_json_failed", error=str(e)))
            return None

    def ingest_syslog(self, raw: str) -> Optional[Dict[str, Any]]:
        """Parse a single syslog line (RFC 5424 or RFC 3164)."""
        try:
            match = SYSLOG_PATTERN.match(raw.strip())
            if not match:
                # Fallback: treat as plain text
                return self._ingest_plain_text(raw, source="syslog")

            pri = int(match.group(1))
            severity = pri % 8
            facility = pri // 8
            hostname = match.group(4) or "unknown"
            app_name = match.group(5) or "unknown"
            message = match.group(8) or ""

            # Extract IPs from the message
            ips = IP_PATTERN.findall(message)
            entity_type = "ip" if ips else "host"
            entity_id = ips[0] if ips else hostname

            score = SYSLOG_SEVERITY_SCORES.get(severity, 20)

            event = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "score": score,
                "evidence": [{
                    "type": "syslog",
                    "text": message[:500],
                    "source": f"{hostname}/{app_name}",
                    "severity": severity,
                    "facility": facility,
                }],
                "ts": time.time(),
            }
            self._record("syslog")
            return event
        except Exception as e:
            self._failed_total += 1
            logger.error(logfmt("ingest_syslog_failed", error=str(e)))
            return None

    def ingest_cef(self, raw: str) -> Optional[Dict[str, Any]]:
        """Parse a Common Event Format (CEF) log line."""
        try:
            match = CEF_PATTERN.match(raw.strip())
            if not match:
                return None

            vendor = match.group(2)
            product = match.group(3)
            sig_id = match.group(5)
            name = match.group(6)
            severity = match.group(7)
            extensions = match.group(8)

            # Parse CEF extensions (key=value pairs)
            ext_dict = {}
            for pair in re.findall(r"(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)", extensions):
                ext_dict[pair[0]] = pair[1]

            # Extract entity
            entity_id = ext_dict.get("src", ext_dict.get("dst", ext_dict.get("dhost", "unknown")))
            entity_type = "ip" if IP_PATTERN.match(entity_id) else "host"

            score = CEF_SEVERITY_SCORES.get(severity.strip(), 30)

            event = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "score": score,
                "evidence": [{
                    "type": "cef",
                    "text": name,
                    "source": f"{vendor}/{product}",
                    "signature_id": sig_id,
                }],
                "ts": time.time(),
            }
            self._record("cef")
            return event
        except Exception as e:
            self._failed_total += 1
            logger.error(logfmt("ingest_cef_failed", error=str(e)))
            return None

    def ingest_csv(self, csv_text: str, column_map: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Parse CSV data with optional column mapping.

        Parameters
        ----------
        csv_text : str
            Raw CSV content.
        column_map : dict, optional
            Maps CSV columns to TelemetryEvent fields.
            Example: {"source_ip": "entity_id", "severity": "score"}
        """
        events = []
        default_map = {
            "src_ip": "entity_id", "source_ip": "entity_id", "ip": "entity_id",
            "src": "entity_id", "address": "entity_id",
            "severity": "score", "risk": "score", "priority": "score",
            "type": "entity_type", "category": "entity_type",
            "message": "evidence_text", "description": "evidence_text",
            "msg": "evidence_text",
        }
        mapping = {**(default_map), **(column_map or {})}

        try:
            reader = csv.DictReader(io.StringIO(csv_text))
            for row in reader:
                entity_id = None
                entity_type = "ip"
                score = 20.0
                evidence_text = ""

                for col, value in row.items():
                    if not col or not value:
                        continue
                    target = mapping.get(col.lower().strip())
                    if target == "entity_id":
                        entity_id = value.strip()
                    elif target == "score":
                        try:
                            score = float(value)
                        except ValueError:
                            pass
                    elif target == "entity_type":
                        entity_type = value.strip().lower()
                    elif target == "evidence_text":
                        evidence_text = value.strip()

                if not entity_id:
                    # Try to find an IP in any column
                    for v in row.values():
                        if v:
                            ips = IP_PATTERN.findall(str(v))
                            if ips:
                                entity_id = ips[0]
                                break

                if entity_id:
                    events.append({
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "score": min(100, max(0, score)),
                        "evidence": [{"type": "csv_import", "text": evidence_text or str(row), "source": "csv"}],
                        "ts": time.time(),
                    })

            self._ingested_total += len(events)
            self._record("csv", count=len(events))
            return events
        except Exception as e:
            self._failed_total += 1
            logger.error(logfmt("ingest_csv_failed", error=str(e)))
            return []

    def _map_generic_json(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Map common SIEM JSON formats to TelemetryEvent."""
        # Try to extract entity from common fields
        entity_id = (
            data.get("src_ip") or data.get("source_ip") or data.get("ip")
            or data.get("src") or data.get("hostname") or data.get("user")
            or data.get("account") or data.get("address")
        )
        if not entity_id:
            return None

        # Determine type
        entity_type = data.get("type", data.get("category", "ip"))
        if entity_type not in ("ip", "user", "host", "domain"):
            entity_type = "ip" if IP_PATTERN.match(str(entity_id)) else "host"

        # Extract score
        score = data.get("score") or data.get("severity") or data.get("risk") or data.get("priority") or 20
        try:
            score = float(score)
        except (ValueError, TypeError):
            score = 20.0

        return {
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "score": min(100, max(0, score)),
            "evidence": [{"type": "json_import", "text": str(data.get("message", data.get("description", "")))[:500], "source": "api"}],
            "ts": data.get("timestamp") or data.get("ts") or time.time(),
        }

    def _ingest_plain_text(self, text: str, source: str = "unknown") -> Optional[Dict[str, Any]]:
        """Fallback: extract IPs from plain text."""
        ips = IP_PATTERN.findall(text)
        if not ips:
            return None
        return {
            "entity_type": "ip",
            "entity_id": ips[0],
            "score": 30,
            "evidence": [{"type": "text_extract", "text": text[:500], "source": source}],
            "ts": time.time(),
        }

    def _record(self, source: str, count: int = 1) -> None:
        self._ingested_total += count
        self._sources[source] = self._sources.get(source, 0) + count
        logger.info(logfmt("event_ingested", source=source, count=count))

    def stats(self) -> Dict[str, Any]:
        return {
            "ingested_total": self._ingested_total,
            "failed_total": self._failed_total,
            "by_source": dict(self._sources),
        }


# Module-level singleton
ingestion_engine = IngestionEngine()
