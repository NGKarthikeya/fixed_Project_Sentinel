from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from forensic.report_models import ForensicReportContext

TEMPLATE_DIR = Path(__file__).parent


def render_report(context: ForensicReportContext) -> str:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return environment.get_template("report_template.html").render(**context.model_dump(mode="json"))


def generate_report_bytes(context: ForensicReportContext) -> bytes:
    html = render_report(context)
    try:
        from weasyprint import HTML
        return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
    except Exception:
        return html.encode("utf-8")


def _extract_auth_status(val) -> str:
    if val is None:
        return "NOT_CHECKED"
    if isinstance(val, str):
        return val or "NOT_CHECKED"
    if isinstance(val, dict):
        res = val.get("status") or val.get("result") or val.get("verdict")
        if res:
            return str(res)
    if hasattr(val, "status") and getattr(val, "status"):
        return str(getattr(val, "status"))
    if hasattr(val, "result") and getattr(val, "result"):
        return str(getattr(val, "result"))
    if hasattr(val, "model_dump"):
        try:
            dump = val.model_dump(mode="json")
            if isinstance(dump, dict):
                res = dump.get("status") or dump.get("result") or dump.get("verdict")
                if res:
                    return str(res)
        except Exception:
            pass
    return str(val) if val else "NOT_CHECKED"


def _analysis_context(email_id: str, email: dict, evidence) -> ForensicReportContext:
    risk = email.get("risk") or {}
    header = email.get("header_analysis") or {}
    intelligence = email.get("extracted_intelligence") or {}
    score = float(risk.get("score", risk.get("risk_score", 0)) or 0)
    return ForensicReportContext(
        report_id=f"report-{uuid4()}",
        email_id=email_id,
        generated_at=datetime.now(timezone.utc),
        generator_version="1.0.0",
        risk_score=max(0, min(100, score)),
        risk_level=str(risk.get("level", risk.get("risk_level", "unknown"))),
        verdict="SCAM" if email.get("is_scam") else "BENIGN",
        evidence=evidence,
        sender={"from_address": email.get("from_email"), "subject": email.get("subject")},
        authentication={
            "spf": _extract_auth_status(header.get("spf")) if isinstance(header, dict) else "NOT_CHECKED",
            "dkim": _extract_auth_status(header.get("dkim")) if isinstance(header, dict) else "NOT_CHECKED",
            "dmarc": _extract_auth_status(header.get("dmarc")) if isinstance(header, dict) else "NOT_CHECKED",
        },
        headers=header if isinstance(header, dict) else {},
        indicators=[{"type": "upi_id", "value": value} for value in intelligence.get("upi_ids", [])]
        + [{"type": "phishing_link", "value": value} for value in intelligence.get("phishing_links", [])],
        limitations=["Report generated from the data retained by the application."],
    )


async def build_report_context(email_id: str, storage) -> ForensicReportContext:
    email = await storage.get_email_analysis_async(email_id)
    if email is None:
        raise ValueError(f"Email analysis not found for {email_id}")
    evidence = await storage.get_evidence_metadata_async(email_id)
    if evidence is None:
        raise ValueError("Evidence metadata is missing for this email")
    return _analysis_context(email_id, email, evidence)


async def generate_report(email_id: str, storage) -> bytes:
    return generate_report_bytes(await build_report_context(email_id, storage))

