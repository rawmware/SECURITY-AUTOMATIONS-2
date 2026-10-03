"""Live finding stream over WebSocket.

Clients connect to ``/stream`` and receive every finding the runner publishes
to the ``findings`` bus topic, plus a heartbeat every 30 seconds so idle
connections (and proxies) know the stream is alive.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

ws_router = APIRouter()

HEARTBEAT_SECONDS = 30


def _finding_payload(finding) -> dict:
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return dict(finding) if isinstance(finding, dict) else {"finding": str(finding)}


@ws_router.websocket("/stream")
async def stream_findings(websocket: WebSocket) -> None:
    """Push findings published on the bus to this socket as JSON."""
    await websocket.accept()
    bus = websocket.app.state.bus
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def _on_finding(finding) -> None:
        # Bus callbacks may fire from other threads; hop onto the loop.
        loop.call_soon_threadsafe(queue.put_nowait, _finding_payload(finding))

    unsubscribe = bus.subscribe("findings", _on_finding)
    try:
        await websocket.send_json(
            {"type": "hello", "ts": datetime.now(timezone.utc).isoformat()}
        )
        while True:
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                await websocket.send_json({"type": "finding", "finding": payload})
            except asyncio.TimeoutError:
                await websocket.send_json(
                    {
                        "type": "heartbeat",
                        "ts": datetime.now(timezone.utc).isoformat(),
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        unsubscribe()
