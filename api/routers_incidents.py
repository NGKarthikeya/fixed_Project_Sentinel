from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import verify_api_key, verify_operator_api_key
from api.logging_utils import logfmt
from policy import apply_action, load_playbooks
from schemas import ActionRequest
from storage import get_audit_log, get_incident, list_incidents

router = APIRouter()
logger = logging.getLogger("honeypot_api")


@router.get("/incidents")
async def incidents(api_key: str = Depends(verify_api_key)):
    return {"incidents": list_incidents()}


@router.get("/playbooks")
async def playbooks(api_key: str = Depends(verify_api_key)):
    return {"playbooks": load_playbooks()}


@router.post("/incidents/{incident_id}/action")
async def take_incident_action(
    incident_id: int,
    body: ActionRequest,
    api_key: str = Depends(verify_operator_api_key),
):
    try:
        result = apply_action(
            int(incident_id),
            body.action,
            actor=body.actor,
            params=body.params,
        )
        logger.info(logfmt("incident_action_ok", incident_id=incident_id, action=body.action, actor=body.actor, result=result.get("result")))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(logfmt("incident_action_failed", incident_id=incident_id, action=body.action, error=exc))
        raise HTTPException(status_code=500, detail="Internal processing error.")


@router.get("/incidents/{incident_id}/audit")
async def incident_audit(incident_id: int, api_key: str = Depends(verify_api_key)):
    incident = get_incident(int(incident_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident": incident, "audit": get_audit_log(int(incident_id))}

