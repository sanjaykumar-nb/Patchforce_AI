"""
PatchForge AI - Real-Time Streaming Endpoints
============================================
Server-Sent Events (SSE) and WebSocket endpoints for streaming live pipeline telemetry.
"""

from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from app.logs.streamer import log_streamer
from app.core.logging import get_logger

logger = get_logger("patchforge.api.stream")
router = APIRouter()


@router.get("/scans/{scan_id}", summary="Stream Scan Telemetry")
async def stream_scan_events(scan_id: str, max_events: Optional[int] = None):
    """Streams live Tree-sitter AST scan progress events via Server-Sent Events (SSE)."""
    return StreamingResponse(
        log_streamer.subscribe(channel_id=f"scan:{scan_id}", max_events=max_events),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/patches/{patch_id}", summary="Stream Patch Validation")
async def stream_patch_events(patch_id: str, max_events: Optional[int] = None):
    """Streams live LLM patch generation and 4-tier validation events via SSE."""
    return StreamingResponse(
        log_streamer.subscribe(channel_id=f"patch:{patch_id}", max_events=max_events),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/live", summary="Stream Global Pipeline Telemetry")
async def stream_global_live_events(max_events: Optional[int] = None):
    """Streams all real-time background worker telemetry across all pipelines."""
    return StreamingResponse(
        log_streamer.subscribe(channel_id=None, max_events=max_events),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws/{channel_id}")
async def websocket_log_endpoint(websocket: WebSocket, channel_id: str):
    """WebSocket terminal connection for high-frequency interactive telemetry."""
    await websocket.accept()
    logger.info(f"WebSocket client connected to channel [{channel_id}]")
    try:
        async for event in log_streamer.subscribe(channel_id=channel_id):
            await websocket.send_text(event)
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from channel [{channel_id}]")
    except Exception as e:
        logger.warning(f"WebSocket error on channel [{channel_id}]: {str(e)}")
