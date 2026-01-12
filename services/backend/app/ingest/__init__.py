"""
Mini-SIEM v1 - Ingestion Package
"""

from app.ingest.auth_ingest import router as auth_router
from app.ingest.suricata_ingest import router as suricata_router
from app.ingest.flow_ingest import router as flow_router

__all__ = ["auth_router", "suricata_router", "flow_router"]
