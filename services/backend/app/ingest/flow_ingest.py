"""
Analytical-Intelligence v1 - Flow Event Ingestion
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session, ensure_device, insert_raw_event, insert_detection
from app.security import verify_api_key
from app.schemas import FlowEventPayload, IngestResponse
from app.detectors.network_ml_detector import analyze_flow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


@router.post("/flow", response_model=IngestResponse)
async def ingest_flow_event(
    payload: FlowEventPayload,
    api_key: str = Depends(verify_api_key),
    session: AsyncSession = Depends(get_session)
):
    """
    Ingest a network flow event.
    Stores the raw event and runs ML classification.
    """
    try:
        # Parse timestamp
        if payload.timestamp:
            try:
                ts = datetime.fromisoformat(payload.timestamp.replace("Z", "+00:00"))
            except:
                ts = datetime.utcnow()
        else:
            ts = datetime.utcnow()
        
        # Ensure device exists
        await ensure_device(session, payload.device_id, payload.hostname, payload.device_ip)
        
        # Store raw event
        event_id = await insert_raw_event(
            session,
            ts=ts,
            device_id=payload.device_id,
            event_type="flow",
            payload=payload.flow
        )
        
        # Run ML detection
        detection_id = None
        detection = analyze_flow(payload.flow)
        
        if detection:
            detection_id = await insert_detection(
                session,
                ts=ts,
                device_id=payload.device_id,
                raw_event_id=event_id,
                model_name=detection["model_name"],
                label=detection["label"],
                score=detection["score"],
                severity=detection["severity"],
                details=detection["details"]
            )
            logger.info(f"Network ML detection: {detection['label']} ({detection['severity']})")
        
        await session.commit()

        return IngestResponse(
            status="accepted",
            event_id=event_id,
            detection_id=detection_id,
            message="Flow event processed"
        )

    except Exception as e:
        await session.rollback()
        logger.error(f"Flow ingestion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
