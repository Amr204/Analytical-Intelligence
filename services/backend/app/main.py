"""
Analytical-Intelligence v1 - Main Application
FastAPI backend with Jinja2 templates
"""

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.models_loader import load_all_models
from app.schemas import HealthResponse, ErrorResponse
from app.ui import router as ui_router
from app.ingest import auth_router, suricata_router
from app.db import ensure_schema

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("=" * 50)
    logger.info("Analytical-Intelligence v1 Starting...")
    logger.info("=" * 50)
    
    # Run database schema migration
    try:
        await ensure_schema()
        logger.info("Database schema migration completed")
    except Exception as e:
        logger.error(f"Database schema migration failed: {e}")
        # Continue anyway - tables may already exist
    
    # Load ML models
    ssh_loaded = load_all_models()
    
    logger.info("-" * 50)
    logger.info("Model Status:")
    logger.info(f"  SSH LSTM:     {'LOADED' if ssh_loaded else 'NOT LOADED'}")
    logger.info("-" * 50)
    
    if not ssh_loaded:
        logger.warning("SSH ML model not loaded - SSH detection capabilities limited")
    
    # Initialize NotificationBus
    from app.notifications import NotificationBus, set_notification_bus
    notification_bus = NotificationBus()
    notification_bus.start()
    set_notification_bus(notification_bus)
    app.state.notification_bus = notification_bus
    
    # Telegram startup test (optional)
    if settings.telegram_enabled and settings.telegram_startup_test:
        from datetime import datetime as dt
        from app.notifications.telegram import TelegramNotifier
        try:
            notifier = TelegramNotifier()
            await notifier.send_message(
                "✅ <b>Analytical-Intelligence</b> started\n"
                f"🕒 {dt.utcnow().isoformat()}Z\n"
                "📡 Telegram alerts active"
            )
            await notifier.close()
            logger.info("Telegram startup test message sent")
        except Exception as e:
            logger.warning(f"Telegram startup test failed: {e}")
    
    logger.info(f"Backend running on {settings.backend_host}:{settings.backend_port}")
    logger.info("=" * 50)
    
    yield
    
    # Shutdown
    logger.info("Analytical-Intelligence v1 Shutting down...")
    
    # Stop NotificationBus
    if hasattr(app.state, 'notification_bus') and app.state.notification_bus:
        await app.state.notification_bus.stop()
        set_notification_bus(None)


# ── OpenAPI tag metadata ────────────────────────────────────────────────
OPENAPI_TAGS = [
    {
        "name": "Health",
        "description": "System health-check and ML model readiness probes.",
    },
    {
        "name": "Dashboard",
        "description": (
            "Aggregate statistics and chart-ready analytics consumed by the web dashboard. "
            "Includes **timeseries**, **severity breakdown**, **top attackers**, and **device heatmaps**."
        ),
    },
    {
        "name": "Incidents",
        "description": (
            "Detection alerts grouped into time-windowed incidents. "
            "Use the **drilldown** endpoint to fetch raw logs for forensic analysis."
        ),
    },
    {
        "name": "Devices",
        "description": (
            "Registered sensor / device inventory. "
            "Each device has an approval status (`allowed` · `pending` · `blocked`) "
            "and real-time online/offline tracking."
        ),
    },
    {
        "name": "Reports",
        "description": "Export filtered detections as **CSV** or **XLSX** files (max 5 000 rows).",
    },
    {
        "name": "Ingestion",
        "description": (
            "Receive raw events from sensor agents deployed on monitored hosts.\n\n"
            "🔑 **All endpoints require the `INGEST_API_KEY` header** — "
            "click **Authorize** above to set it."
        ),
    },
]


# Create FastAPI app
app = FastAPI(
    title="Analytical-Intelligence API",
    description=(
        "### Real-time Security Information & Event Management (SIEM)\n\n"
        "---\n\n"
        "| Capability | Description |\n"
        "| :--- | :--- |\n"
        "| **SSH Anomaly Detection** | LSTM-based model detects brute-force & lateral movement |\n"
        "| **Suricata IDS** | Ingests & deduplicates IDS alerts with bucket windowing |\n"
        "| **Live Dashboard** | Real-time charts, severity breakdown, top attackers |\n"
        "| **Device Inventory** | Auto-registers sensors with approval workflow |\n"
        "| **Report Export** | One-click CSV / XLSX exports with severity & device filters |\n\n"
        "---\n\n"
        "#### Authentication\n\n"
        "| Method | Scope | How |\n"
        "| :--- | :--- | :--- |\n"
        "| **Session cookie** | Web UI pages | Login via `/login` |\n"
        "| **API Key header** | `/api/v1/ingest/*` | `INGEST_API_KEY` header — click 🔒 **Authorize** above |\n"
        "| **None** | Read-only JSON APIs | Protected by network policy |\n\n"
    ),
    version="1.0.0",
    contact={
        "name": "Analytical-Intelligence Team",
        "url": settings.app_github_url or None,
    },
    license_info={
        "name": "MIT",
    },
    openapi_tags=OPENAPI_TAGS,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# Paths that don't require login
PUBLIC_PATHS = {"/login", "/logout"}
PUBLIC_PREFIXES = ("/static/", "/api/", "/docs", "/redoc", "/openapi.json")


from starlette.middleware.base import BaseHTTPMiddleware


class RequireLoginMiddleware(BaseHTTPMiddleware):
    """Middleware to require login for UI routes."""
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Skip auth check for public paths and prefixes
        if path in PUBLIC_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES):
            return await call_next(request)
        
        # Check if user is logged in
        user_id = request.session.get("user_id")
        if not user_id:
            # Redirect to login with next parameter
            next_url = str(request.url)
            login_url = f"/login?{urlencode({'next': next_url})}"
            return RedirectResponse(url=login_url, status_code=303)
        
        return await call_next(request)


# IMPORTANT: Middleware order is LIFO (last-in-first-out)
# So we add RequireLoginMiddleware FIRST, then SessionMiddleware
# This means SessionMiddleware runs FIRST (sets up session), then RequireLoginMiddleware runs
app.add_middleware(RequireLoginMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.ui_session_secret,
    session_cookie="ai_session",
    max_age=86400,  # 24 hours
)


# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include routers
app.include_router(ui_router)
app.include_router(auth_router)

app.include_router(suricata_router)


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Service health check",
    description="Returns the current service status, UTC timestamp, and API version. "
                "Used by Docker HEALTHCHECK and monitoring systems.",
    responses={
        200: {"description": "Service is healthy"},
    },
)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.utcnow().isoformat() + "Z",
        version="1.0.0"
    )


from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.templating import Jinja2Templates

# Templates for error pages
error_templates = Jinja2Templates(directory="app/templates")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions (404, etc.) - don't convert to 500."""
    # For API routes, return JSON
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail or "Error"}
        )
    
    # For UI routes, return HTML error page
    template_name = "404.html" if exc.status_code == 404 else "error.html"
    try:
        return error_templates.TemplateResponse(
            template_name,
            {
                "request": request,
                "message": exc.detail or f"Error {exc.status_code}",
                "status_code": exc.status_code,
                "page_title": f"Error {exc.status_code}"
            },
            status_code=exc.status_code
        )
    except Exception:
        # Fallback if template not found
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail or "Error"}
        )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unexpected errors only."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=True
    )
