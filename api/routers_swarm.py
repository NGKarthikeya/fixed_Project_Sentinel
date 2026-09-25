from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from api.dependencies import verify_api_key, verify_operator_api_key
from api.logging_utils import logfmt
from api.runtime import runtime_state
from api.services import broadcast_message, control_simulation_service, reset_runtime_state, start_swarm_service, stop_swarm_service
from ant_agents import swarm_coordinator
from containment import containment_engine
from schemas import ContainmentActionRequest, SimulationControl
from swarm_graph import pheromone_graph
from telemetry_simulator import TelemetrySimulator

router = APIRouter()
logger = logging.getLogger("honeypot_api")


@router.post("/containment/action")
async def containment_action(
    body: ContainmentActionRequest,
    api_key: str = Depends(verify_operator_api_key),
):
    result = containment_engine.execute_action(
        action=body.action,
        entity_id=body.entity_id,
        entity_type=body.entity_type,
        actor=body.actor,
        reason=body.reason,
        incident_id=body.incident_id,
        ttl_seconds=body.ttl_seconds,
    )
    if result.get("status") != "ok":
        runtime_state.metrics.containment_failures += 1
        logger.warning(logfmt("containment_action_failed", action=body.action, entity_id=body.entity_id, status=result.get("status")))
        return result

    runtime_state.metrics.containment_actions += 1
    await broadcast_message("containment_action", result)
    logger.info(logfmt("containment_action_ok", action=body.action, entity_id=body.entity_id, entity_type=body.entity_type))
    return result


@router.get("/containment/blocklist")
async def get_blocklist(api_key: str = Depends(verify_api_key)):
    return {"blocklist": containment_engine.get_blocklist()}


@router.get("/containment/audit")
async def get_containment_audit(
    entity_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    api_key: str = Depends(verify_api_key),
):
    return {"audit": containment_engine.get_audit_trail(entity_id=entity_id, limit=limit)}


@router.get("/swarm/status")
async def swarm_status(api_key: str = Depends(verify_api_key)):
    status = swarm_coordinator.get_status()
    status["graph_stats"] = pheromone_graph.get_stats()
    status["simulation_running"] = runtime_state.simulation_running
    return status


@router.get("/swarm/graph")
async def swarm_graph_snapshot(api_key: str = Depends(verify_api_key)):
    return pheromone_graph.to_snapshot()


@router.get("/swarm/hotspots")
async def swarm_hotspots(top_n: int = Query(default=10, ge=1, le=100), api_key: str = Depends(verify_api_key)):
    return {"hotspots": pheromone_graph.get_hotspots(top_n=top_n)}


@router.get("/swarm/corridors")
async def swarm_corridors(min_strength: float = Query(default=0.5, ge=0.0, le=100.0), api_key: str = Depends(verify_api_key)):
    return {"corridors": pheromone_graph.get_attack_corridors(min_strength=min_strength)}


@router.get("/swarm/activity")
async def swarm_activity(limit: int = Query(default=20, ge=1, le=200), api_key: str = Depends(verify_api_key)):
    return {"activity": swarm_coordinator.get_recent_activity(limit=limit)}


@router.get("/swarm/scenarios")
async def list_scenarios(api_key: str = Depends(verify_api_key)):
    sim = TelemetrySimulator()
    return {"scenarios": sim.get_available_scenarios()}


@router.post("/swarm/reset")
async def reset_swarm(api_key: str = Depends(verify_operator_api_key)):
    return await reset_runtime_state()


@router.post("/swarm/simulate")
async def control_simulation(
    body: SimulationControl,
    api_key: str = Depends(verify_operator_api_key),
):
    return await control_simulation_service(body.action, body.scenario or "apt_killchain", body.events_per_second)


@router.post("/swarm/start")
async def start_swarm(api_key: str = Depends(verify_operator_api_key)):
    return await start_swarm_service()


@router.post("/swarm/stop")
async def stop_swarm(api_key: str = Depends(verify_operator_api_key)):
    return await stop_swarm_service()

