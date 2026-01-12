"""
Mini-SIEM v1 - Suricata Event Ingestion
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session, ensure_device, insert_raw_event, insert_detection
from app.security import verify_api_key
from app.schemas import SuricataEventPayload, IngestResponse
from app.detectors.severity import get_suricata_severity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


@router.post("/suricata", response_model=IngestResponse)
async def ingest_suricata_event(
    payload: SuricataEventPayload,
    api_key: str = Depends(verify_api_key),
    session: AsyncSession = Depends(get_session)
):
    """
    Ingest a Suricata eve.json event.
    Stores the raw event and creates a detection for alerts.
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
            event_type="suricata",
            payload=payload.event
        )
        
        detection_id = None
        
        # Create detection for alert events
        event = payload.event
        event_type = event.get("event_type", "")
        
        if event_type == "alert" and "alert" in event:
            alert = event["alert"]
            signature = alert.get("signature", "Unknown Suricata Alert")
            category = alert.get("category", "")
            suricata_severity = alert.get("severity")
            
            # Determine severity
            severity = get_suricata_severity(signature, category, suricata_severity)
            
            # Build label
            label = signature
            if category:
                label = f"{signature} [{category}]"
            
            # Build details
            details = {
                "signature_id": alert.get("signature_id"),
                "signature": signature,
                "category": category,
                "suricata_severity": suricata_severity,
                "action": alert.get("action"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
            }
            
            detection_id = await insert_detection(
                session,
                ts=ts,
                device_id=payload.device_id,
                raw_event_id=event_id,
                model_name="suricata",
                label=label[:255],  # Truncate if needed
                score=1.0,
                severity=severity,
                details=details
            )
            
            logger.info(f"Suricata detection: {signature[:50]} ({severity})")
        
        return IngestResponse(
            status="accepted",
            event_id=event_id,
            detection_id=detection_id,
            message="Suricata event processed"
        )
        
    except Exception as e:
        logger.error(f"Suricata ingestion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
