"""
Analytical-Intelligence v1 - Auth Event Ingestion
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session, ensure_device, insert_raw_event, insert_detection
from app.security import verify_api_key
from app.schemas import AuthEventPayload, IngestResponse
from app.detectors.ssh_lstm_detector import analyze_auth_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


@router.post("/auth", response_model=IngestResponse)
async def ingest_auth_event(
    payload: AuthEventPayload,
    api_key: str = Depends(verify_api_key),
    session: AsyncSession = Depends(get_session)
):
    """
    Ingest an auth.log event.
    Stores the raw event and runs SSH LSTM detection.
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
        event_payload = {
            "line": payload.line,
            "hostname": payload.hostname,
            "device_ip": payload.device_ip,
        }
        
        event_id = await insert_raw_event(
            session,
            ts=ts,
            device_id=payload.device_id,
            event_type="auth",
            payload=event_payload
        )
        
        logger.info(f"Auth event stored: event_id={event_id}, device={payload.device_id}")
        
        # Run SSH LSTM detection
        detection_id = None
        logger.debug(f"Running SSH detection on line: {payload.line[:80]}...")
        detection = analyze_auth_event(payload.line, ts)
        
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
            logger.info(f"SSH detection INSERTED: id={detection_id}, label={detection['label']}, score={detection['score']:.4f}, device={payload.device_id}")
            
            # Enqueue Telegram alert (non-blocking)
            from app.notifications import get_notification_bus
            bus = get_notification_bus()
            if bus:
                details = detection.get("details", {})
                bus.enqueue_alert({
                    "detection_id": detection_id,
                    "timestamp": ts.isoformat() + "Z",
                    "device_id": payload.device_id,
                    "model_name": detection["model_name"],
                    "label": detection["label"],
                    "score": detection["score"],
                    "severity": detection["severity"],
                    "src_ip": details.get("src_ip"),
                    "dst_ip": details.get("target_ip") or payload.device_ip,
                    "dst_port": details.get("port", 22),
                    "protocol": "SSH",
                    "reason": details.get("reason", ""),
                })
        else:
            logger.debug(f"SSH detection returned None for event_id={event_id}")
        
        await session.commit()

        return IngestResponse(
            status="accepted",
            event_id=event_id,
            detection_id=detection_id,
            message="Auth event processed"
        )

    except Exception as e:
        await session.rollback()
        logger.error(f"Auth ingestion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
