"""
SentinelCloud-Advanced Backend
==============================
Main entry point. FastAPI + Socket.IO ASGI application.

Usage:
    python -m backend.main           # or
    uvicorn backend.main:app --host 0.0.0.0 --port 5050

Environment:
    SENTINEL_MODE=dev|lab|live
    SENTINEL_ADMIN_USER=admin
    SENTINEL_ADMIN_PASSWORD=<password>
    SENTINEL_SECRET_KEY=<random-hex>
"""

import sys
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env before anything else
load_dotenv()

import socketio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.api.routes import all_routers
from backend.websocket.manager import sio, broadcast_event, broadcast_detection, broadcast_incident, broadcast_action, broadcast_service_update
from backend.pipeline.processor import pipeline

# ── Logging ──

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("sentinel")


# ── Wire pipeline callbacks to WebSocket broadcasts ──

def _wire_websocket_callbacks():
    """Connect pipeline events to WebSocket broadcasts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()

    def on_event(event):
        try:
            asyncio.run_coroutine_threadsafe(broadcast_event(event), loop)
        except Exception:
            pass

    def on_detection(detection):
        try:
            asyncio.run_coroutine_threadsafe(broadcast_detection(detection), loop)
        except Exception:
            pass

    def on_incident(incident):
        try:
            asyncio.run_coroutine_threadsafe(broadcast_incident(incident), loop)
        except Exception:
            pass

    def on_action(action):
        try:
            asyncio.run_coroutine_threadsafe(broadcast_action(action), loop)
        except Exception:
            pass

    def on_service_update(name, service):
        try:
            asyncio.run_coroutine_threadsafe(broadcast_service_update(name, service), loop)
        except Exception:
            pass

    pipeline.set_callbacks(
        on_event=on_event,
        on_detection=on_detection,
        on_incident=on_incident,
        on_action=on_action,
        on_service_update=on_service_update,
    )


# ── App Lifecycle ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown hooks."""
    logger.info("═" * 60)
    logger.info("  SentinelCloud-Advanced Backend")
    logger.info("  Mode: %s", settings.mode.value.upper())
    logger.info("  Port: %d", settings.port)
    logger.info("═" * 60)

    if settings.mode.value == "dev":
        logger.info("  ⚠ DEV MODE — no real infrastructure required")
        logger.info("  Events will be processed by in-process ML pipeline")
    elif settings.mode.value == "lab":
        logger.info("  🔬 LAB MODE — Docker Compose infrastructure")
    else:
        logger.info("  🛡 LIVE MODE — Full K8s cluster")

    # Ensure data directory exists
    data_dir = Path(settings.sqlite_path).parent
    data_dir.mkdir(parents=True, exist_ok=True)

    # Wire WebSocket callbacks
    _wire_websocket_callbacks()

    logger.info("Pipeline initialized: detector=%s, threshold=%.2f",
                pipeline.detector._model_version, pipeline.detector.threshold)
    logger.info("═" * 60)

    # Start live clinical telemetry and attack generator
    from backend.pipeline.live_traffic_generator import LiveTrafficGenerator
    traffic_generator = LiveTrafficGenerator(pipeline)
    traffic_generator.start()

    yield

    traffic_generator.stop()
    logger.info("SentinelCloud backend shutting down")


# ── FastAPI App ──

fastapi_app = FastAPI(
    title="SentinelCloud-Advanced API",
    description="eBPF-Driven Autonomous Cyber-Resilience for Medical Microservices",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=r"https://.*\.vercel\.app|https://.*\.pages\.dev|https?://localhost(:\d+)?|https?://127\.0\.0\.1(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all API routes
for router in all_routers:
    fastapi_app.include_router(router)

# Mount Socket.IO
app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info",
    )
