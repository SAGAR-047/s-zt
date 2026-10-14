"""
SentinelCloud WebSocket Manager
================================
Real-time push via Socket.IO.
Handles connections, rooms, and event broadcasting.
"""

import logging
from typing import Any, Optional

import socketio

from backend.config import settings
from backend.core.event_schema import (
    TelemetryEvent, DetectionResult, Incident, MitigationAction, ServiceInfo
)

logger = logging.getLogger("sentinel.websocket")

# Create Socket.IO server
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
)

# Connection tracking
connected_clients: dict[str, dict] = {}  # sid -> {username, role, connected_at}


@sio.event
async def connect(sid, environ, auth_data=None):
    """Handle new WebSocket connection."""
    logger.info("WebSocket client connected: %s", sid)
    connected_clients[sid] = {
        "connected_at": "now",
        "username": "unknown",
        "role": "unknown",
    }
    # Send current mode
    await sio.emit("mode", {"mode": settings.mode.value}, to=sid)


@sio.event
async def disconnect(sid):
    """Handle WebSocket disconnection."""
    logger.info("WebSocket client disconnected: %s", sid)
    connected_clients.pop(sid, None)


@sio.event
async def authenticate(sid, data):
    """Authenticate WebSocket connection with token."""
    from backend.auth.service import auth_service
    token = data.get("token", "")
    payload = auth_service.verify_token(token)
    if payload:
        connected_clients[sid] = {
            "username": payload.sub,
            "role": payload.role,
            "connected_at": "now",
        }
        await sio.emit("authenticated", {
            "username": payload.sub,
            "role": payload.role,
        }, to=sid)
        logger.info("WebSocket authenticated: %s (role=%s)", payload.sub, payload.role)
    else:
        await sio.emit("auth_error", {"message": "Invalid token"}, to=sid)


@sio.event
async def request_state(sid, data=None):
    """Client requests full state snapshot."""
    from backend.pipeline.processor import pipeline
    state = pipeline.get_state_snapshot()
    await sio.emit("state_snapshot", state, to=sid)


# ── Broadcasting Functions ──

async def broadcast_event(event: TelemetryEvent):
    """Push telemetry event to all connected clients."""
    await sio.emit("telemetry_event", event.model_dump(mode="json"))


async def broadcast_detection(detection: DetectionResult):
    """Push detection result to all connected clients."""
    if detection.is_anomaly or detection.is_sequence_anomaly:
        await sio.emit("detection_alert", detection.model_dump(mode="json"))
    else:
        await sio.emit("detection_result", detection.model_dump(mode="json"))


async def broadcast_incident(incident: Incident):
    """Push incident update to all connected clients."""
    await sio.emit("incident_update", incident.model_dump(mode="json"))


async def broadcast_action(action: MitigationAction):
    """Push mitigation action to all connected clients."""
    await sio.emit("action_update", action.model_dump(mode="json"))


async def broadcast_service_update(name: str, service: ServiceInfo):
    """Push service status change."""
    await sio.emit("service_update", {
        "name": name,
        "service": service.model_dump(mode="json"),
    })


async def broadcast_metrics(metrics: dict):
    """Push metrics update."""
    await sio.emit("metrics_update", metrics)
