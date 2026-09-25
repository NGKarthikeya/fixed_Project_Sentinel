from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from api.dependencies import is_rate_limited, verify_api_key
from api.logging_utils import logfmt
from api.runtime import runtime_state
from event_queue import event_queue
from ingestion import ingestion_engine
from schemas import CSVIngestRequest, JSONIngestRequest, SyslogIngestRequest, TelemetryEvent

router = APIRouter()
logger = logging.getLogger("honeypot_api")


@router.post("/telemetry", status_code=202)
async def ingest_telemetry(
    body: TelemetryEvent,
    api_key: str = Depends(verify_api_key),
):
    """Queue a telemetry event for async processing.

    Returns 202 Accepted immediately. The event will be processed
    by the background batch handler which runs detectors, deposits
    pheromones, evaluates correlation, and broadcasts updates.
    """
    runtime_state.metrics.telemetry_requests += 1
    event = body.model_dump()
    accepted = await event_queue.enqueue(event)
    if not accepted:
        runtime_state.metrics.telemetry_failures += 1
        logger.warning(logfmt("telemetry_backpressure", entity_id=body.entity_id))
        raise HTTPException(status_code=429, detail="Queue full — backpressure active.")

    logger.info(logfmt("telemetry_enqueued", entity_type=body.entity_type, entity_id=body.entity_id, queue_depth=event_queue.metrics.depth))
    return {
        "status": "accepted",
        "queue_depth": event_queue.metrics.depth,
    }


@router.post("/ingest/json", status_code=202)
async def ingest_json(
    request: Request,
    body: JSONIngestRequest,
    api_key: str = Depends(verify_api_key),
):
    client_ip = request.client.host if request.client else "unknown"
    if is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    event = ingestion_engine.ingest_json(body.root)
    if not event:
        runtime_state.metrics.record_ingest("json", success=False)
        logger.warning(logfmt("json_ingest_unparseable"))
        raise HTTPException(status_code=422, detail="Could not parse event")

    try:
        event = TelemetryEvent.model_validate(event).model_dump()
    except ValidationError as exc:
        runtime_state.metrics.record_ingest("json", success=False)
        logger.warning(logfmt("json_ingest_invalid_normalized_event"))
        raise HTTPException(status_code=422, detail="Normalized event failed validation.") from exc

    accepted = await event_queue.enqueue(event)
    runtime_state.metrics.record_ingest("json", success=accepted)
    if not accepted:
        logger.warning(logfmt("json_ingest_backpressure"))
        raise HTTPException(status_code=429, detail="Queue full — backpressure active.")

    logger.info(logfmt("json_ingest_enqueued", entity_id=event.get("entity_id")))
    return {"status": "accepted", "queue_depth": event_queue.metrics.depth}


@router.post("/ingest/syslog", status_code=202)
async def ingest_syslog(
    body: SyslogIngestRequest,
    api_key: str = Depends(verify_api_key),
):
    lines = body.raw if isinstance(body.raw, list) else [body.raw]
    enqueued = 0

    for line in lines[:100]:
        event = ingestion_engine.ingest_syslog(str(line))
        if event:
            accepted = await event_queue.enqueue(event)
            if accepted:
                enqueued += 1

    if not enqueued:
        runtime_state.metrics.record_ingest("syslog", success=False)
        logger.warning(logfmt("syslog_ingest_empty", line_count=len(lines)))
        return {"status": "accepted", "enqueued": 0}

    runtime_state.metrics.record_ingest("syslog", success=True)
    logger.info(logfmt("syslog_ingest_enqueued", line_count=len(lines), enqueued=enqueued))
    return {"status": "accepted", "enqueued": enqueued, "queue_depth": event_queue.metrics.depth}


@router.post("/ingest/csv", status_code=202)
async def ingest_csv(
    body: CSVIngestRequest,
    api_key: str = Depends(verify_api_key),
):
    events = ingestion_engine.ingest_csv(body.csv, body.column_map)
    enqueued = 0
    for event in events:
        accepted = await event_queue.enqueue(event)
        if accepted:
            enqueued += 1

    if not enqueued:
        runtime_state.metrics.record_ingest("csv", success=False)
        logger.warning(logfmt("csv_ingest_empty"))
        return {"status": "accepted", "enqueued": 0}

    runtime_state.metrics.record_ingest("csv", success=True)
    logger.info(logfmt("csv_ingest_enqueued", event_count=len(events), enqueued=enqueued))
    return {"status": "accepted", "enqueued": enqueued, "queue_depth": event_queue.metrics.depth}

