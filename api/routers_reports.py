from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

import storage
from api.dependencies import get_client_ip, is_rate_limited, verify_forensic_read_api_key
from api.logging_utils import logfmt
from forensic.forensic_report import generate_report

router = APIRouter()
logger = logging.getLogger("honeypot_api")


def _safe_report_filename(email_id: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", email_id or "report")
    return value.strip("-_. ") or "report"


@router.get("/emails/{email_id}/report", response_class=Response)
async def download_forensic_report(
    email_id: str,
    request: Request,
    api_key: str = Depends(verify_forensic_read_api_key),
):
    client_ip = get_client_ip(request)
    if is_rate_limited(client_ip):
        logger.warning(logfmt("report_rate_limited", client_ip=client_ip, email_id=email_id))
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    try:
        report_bytes = await generate_report(email_id, storage)
    except ValueError as exc:
        if "Evidence metadata" in str(exc):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        raise HTTPException(status_code=404, detail="Email analysis not found") from exc
    storage.log_report_generation("forensic_report_generated", email_id, "api_user", f"report-{email_id}")
    logger.info(logfmt("forensic_report_generated", email_id=email_id))
    media_type = "application/pdf" if report_bytes.startswith(b"%PDF") else "text/html"
    return Response(
        content=report_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="forensic-report-{_safe_report_filename(email_id)}.pdf"'},
    )


@router.get("/emails/{email_id}/report/metadata")
async def forensic_report_metadata(
    email_id: str,
    request: Request,
    api_key: str = Depends(verify_forensic_read_api_key),
):
    client_ip = get_client_ip(request)
    if is_rate_limited(client_ip):
        logger.warning(logfmt("report_metadata_rate_limited", client_ip=client_ip, email_id=email_id))
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    analysis = storage.get_email_analysis(email_id)
    evidence = storage.get_evidence_metadata(email_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Email analysis not found")
    if evidence is None:
        raise HTTPException(status_code=409, detail="Evidence metadata is missing for this email")
    return {
        "email_id": email_id,
        "report_id": f"report-{email_id}",
        "risk_score": (analysis.get("risk") or {}).get("score", 0),
        "verdict": "SCAM" if analysis.get("is_scam") else "BENIGN",
        "evidence": {"sha256": evidence.sha256, "captured_at": evidence.captured_at.isoformat(), "integrity_status": evidence.integrity_status},
    }

