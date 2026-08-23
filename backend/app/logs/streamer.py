"""
PatchForge AI - Real-Time Pipeline Log Streamer
===============================================
Asynchronous pub/sub event broadcaster streaming Tree-sitter AST traversals,
Docker sandbox stdout/stderr, and LLM patch generation stages via Server-Sent Events (SSE)
and WebSockets.
"""

import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, Set, Any, AsyncGenerator, Optional
from app.core.logging import get_logger

logger = get_logger("patchforge.logs.streamer")


class LogEventStreamer:
    """In-memory async Pub/Sub event broadcaster for real-time telemetry."""

    def __init__(self):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._global_subscribers: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    def format_sse(self, event_type: str, data: Any) -> str:
        """Formats a structured payload into Server-Sent Events wire format."""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "data": data,
        }
        return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

    async def subscribe(
        self,
        channel_id: Optional[str] = None,
        max_events: Optional[int] = None,
    ) -> AsyncGenerator[str, None]:
        """Subscribes an async client to a specific channel or global pipeline feed."""
        queue: asyncio.Queue = asyncio.Queue()

        async with self._lock:
            if channel_id:
                if channel_id not in self._subscribers:
                    self._subscribers[channel_id] = set()
                self._subscribers[channel_id].add(queue)
            else:
                self._global_subscribers.add(queue)

        # Send initial connected handshake event
        yield self.format_sse(
            "CONNECTED",
            {"status": "STREAM_ACTIVE", "channel": channel_id or "global", "connected_at": datetime.now(timezone.utc).isoformat()},
        )

        event_count = 0
        try:
            while True:
                if max_events and event_count >= max_events:
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield msg
                    event_count += 1
                    if "PIPELINE_COMPLETE" in msg or "PIPELINE_FAILED" in msg:
                        break
                except asyncio.TimeoutError:
                    # Yield heartbeat keepalive
                    yield self.format_sse("HEARTBEAT", {"time": datetime.now(timezone.utc).isoformat()})
                    if max_events:
                        event_count += 1
        except asyncio.CancelledError:
            pass
        finally:
            async with self._lock:
                if channel_id and channel_id in self._subscribers:
                    self._subscribers[channel_id].discard(queue)
                    if not self._subscribers[channel_id]:
                        del self._subscribers[channel_id]
                else:
                    self._global_subscribers.discard(queue)

    async def broadcast(self, event_type: str, data: Any, channel_id: Optional[str] = None):
        """Broadcasts an event message to subscribed channel listeners."""
        msg = self.format_sse(event_type, data)

        async with self._lock:
            # Channel-specific subscribers
            if channel_id and channel_id in self._subscribers:
                for q in list(self._subscribers[channel_id]):
                    await q.put(msg)

            # Global subscribers
            for q in list(self._global_subscribers):
                await q.put(msg)


# Global event streamer singleton
log_streamer = LogEventStreamer()
