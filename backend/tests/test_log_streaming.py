"""
PatchForge AI - Phase 16 Real-Time Log Streaming Unit Tests
===========================================================
Validates async pub/sub log streamer, SSE wire formatting, channel subscriptions,
and FastAPI streaming telemetry endpoints.
"""

import json
import pytest
import asyncio
from fastapi.testclient import TestClient

from app.main import app
from app.logs.streamer import log_streamer

client = TestClient(app)


@pytest.mark.asyncio
async def test_log_streamer_formatting_and_pubsub():
    event_type = "AST_PARSED"
    data = {"file": "app.py", "nodes_count": 42}

    formatted = log_streamer.format_sse(event_type, data)
    assert f"event: {event_type}" in formatted
    assert '"nodes_count": 42' in formatted
    assert formatted.endswith("\n\n")


@pytest.mark.asyncio
async def test_log_streamer_channel_broadcast():
    channel = "scan:test-channel-999"
    sub_generator = log_streamer.subscribe(channel_id=channel, max_events=2)

    # First event is CONNECTED handshake
    connected_event = await sub_generator.__anext__()
    assert "CONNECTED" in connected_event
    assert "STREAM_ACTIVE" in connected_event

    # Broadcast event
    await log_streamer.broadcast(
        event_type="FINDING_DETECTED",
        data={"cwe": "CWE-89", "rule": "PY-SQLI-001"},
        channel_id=channel,
    )

    received = await sub_generator.__anext__()
    assert "FINDING_DETECTED" in received
    assert "CWE-89" in received


def test_api_stream_endpoints_headers():
    # 1. Scan stream endpoint
    resp = client.get("/api/v1/stream/scans/test-scan-123?max_events=1", headers={"Accept": "text/event-stream"})
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    assert "CONNECTED" in resp.text

    # 2. Patch stream endpoint
    resp = client.get("/api/v1/stream/patches/test-patch-456?max_events=1", headers={"Accept": "text/event-stream"})
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    assert "CONNECTED" in resp.text

    # 3. Global live stream endpoint
    resp = client.get("/api/v1/stream/live?max_events=1", headers={"Accept": "text/event-stream"})
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    assert "CONNECTED" in resp.text
