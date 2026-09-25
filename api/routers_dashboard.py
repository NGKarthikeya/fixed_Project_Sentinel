from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from api.logging_utils import logfmt
from api.dependencies import authorize_websocket
from api.runtime import MAX_LIVE_WS_MESSAGE_BYTES, runtime_state
from api.services import handle_ws_message, serve_dashboard_response, websocket_init_payload

router = APIRouter()
logger = logging.getLogger("honeypot_api")

dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    if not await authorize_websocket(websocket):
        return
    if not await runtime_state.ws_manager.connect(websocket):
        return
    try:
        await websocket.send_text(json.dumps(await websocket_init_payload(), default=str))
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if len(data.encode("utf-8")) > MAX_LIVE_WS_MESSAGE_BYTES:
                    await websocket.close(code=1009, reason="Message too large")
                    break
                await handle_ws_message(json.loads(data), websocket)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "heartbeat", "timestamp": time.time()}))
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.exception(logfmt("websocket_error", error=exc))
    finally:
        runtime_state.ws_manager.disconnect(websocket)


@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    return serve_dashboard_response(dashboard_dir)

