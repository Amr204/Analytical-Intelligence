"""
Analytical-Intelligence v1 - Main Application
FastAPI backend with Jinja2 templates
"""

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.config import settings
from app.models_loader import load_all_models
from app.schemas import HealthResponse
from app.ui import router as ui_router
from app.ingest import auth_router, flow_router

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
    
    # Load ML models
    ssh_loaded, network_loaded = load_all_models()
    
    logger.info("-" * 50)
    logger.info("Model Status:")
    logger.info(f"  SSH LSTM:     {'LOADED' if ssh_loaded else 'NOT LOADED'}")
    logger.info(f"  Network RF:   {'LOADED' if network_loaded else 'NOT LOADED'}")
    logger.info("-" * 50)
    
    if not ssh_loaded and not network_loaded:
        logger.warning("No ML models loaded - detection capabilities limited")
    
    logger.info(f"Backend running on {settings.backend_host}:{settings.backend_port}")
    logger.info("=" * 50)
    
    yield
    
    # Shutdown
    logger.info("Analytical-Intelligence v1 Shutting down...")


# Create FastAPI app
app = FastAPI(
    title="Analytical-Intelligence v1",
    description="Real-time Security Information and Event Management",
    version="1.0.0",
    lifespan=lifespan
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include routers
app.include_router(ui_router)
app.include_router(auth_router)
app.include_router(flow_router)


@app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.utcnow().isoformat() + "Z",
        version="1.0.0"
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
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
