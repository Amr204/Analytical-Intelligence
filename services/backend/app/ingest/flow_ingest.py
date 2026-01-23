"""
Analytical-Intelligence v1 - Flow Event Ingestion
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy import text

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session, ensure_device, insert_raw_event, insert_detection
from app.security import verify_api_key
from app.schemas import FlowEventPayload, IngestResponse
from app.detectors.network_ml_detector import analyze_flow
from app.config import settings

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
            label = detection["label"]
            details = detection["details"]
            src_ip = details.get("src_ip", "")
            dst_ip = details.get("dst_ip", "")
            src_port = details.get("src_port", 0)
            dst_port = details.get("dst_port", 0)
            proto = details.get("protocol", "")
            
            # --- Deduplication Logic ---
            # Check for existing detection with same label and flow tuple within dedup window
            # Uses indexed columns for better performance
            dedup_window = settings.ml_dedup_window_seconds
            dedup_cutoff = ts - timedelta(seconds=dedup_window)
            
            dedup_query = text("""
                SELECT id, occurrences 
                FROM detections 
                WHERE model_name = 'network_rf'
                AND label = :label
                AND ts > :cutoff
                AND src_ip = :src_ip
                AND dst_ip = :dst_ip
                AND dst_port = :dst_port
                ORDER BY ts DESC 
                LIMIT 1
            """)
            
            result = await session.execute(dedup_query, {
                "label": label,
                "cutoff": dedup_cutoff,
                "src_ip": str(src_ip) if src_ip else "",
                "dst_ip": str(dst_ip) if dst_ip else "",
                "dst_port": int(dst_port) if dst_port else 0
            })
            existing = result.first()
            
            if existing:
                # Update existing
                detection_id = existing[0]
                new_occurrences = (existing[1] or 1) + 1
                await session.execute(text("""
                    UPDATE detections 
                    SET occurrences = :occurrences, last_seen = :ts
                    WHERE id = :id
                """), {"occurrences": new_occurrences, "ts": ts, "id": detection_id})
                logger.info(f"Network RF detection DEDUP: {label} (x{new_occurrences})")
            else:
                # --- Cooldown Logic ---
                # If no dedup match, check if we are in cooldown for this (src_ip, label) pair
                # Changed from per-IP only to per (IP, label) so different attack types
                # from the same IP can still create detections
                cooldown_window = settings.ml_cooldown_seconds_per_src
                cooldown_cutoff = ts - timedelta(seconds=cooldown_window)
                
                cooldown_query = text("""
                    SELECT id, ts
                    FROM detections 
                    WHERE model_name = 'network_rf'
                    AND src_ip = :src_ip
                    AND label = :label
                    AND ts > :cutoff
                    ORDER BY ts DESC
                    LIMIT 1
                """)
                
                # Check for recent detection from this IP with the SAME label
                result = await session.execute(cooldown_query, {
                    "src_ip": str(src_ip) if src_ip else "",
                    "label": label,
                    "cutoff": cooldown_cutoff
                })
                cooldown_hit = result.first()
                
                if cooldown_hit:
                    # Calculate remaining cooldown for informative logging
                    last_detection_ts = cooldown_hit[1] if len(cooldown_hit) > 1 else None
                    remaining = "unknown"
                    if last_detection_ts:
                        elapsed = (ts - last_detection_ts).total_seconds()
                        remaining = f"{int(cooldown_window - elapsed)}s"
                    logger.info(f"Network RF detection SUPPRESSED (Cooldown): {label} from {src_ip}, remaining~{remaining}")
                else:
                    # Insert new detection with network fields for dedup optimization
                    detection_id = await insert_detection(
                        session,
                        ts=ts,
                        device_id=payload.device_id,
                        raw_event_id=event_id,
                        model_name=detection["model_name"],
                        label=detection["label"],
                        score=detection["score"],
                        severity=detection["severity"],
                        details=detection["details"],
                        occurrences=1,
                        first_seen=ts,
                        last_seen=ts,
                        # Network fields for indexed queries
                        src_ip=str(src_ip) if src_ip else None,
                        dst_ip=str(dst_ip) if dst_ip else None,
                        src_port=int(src_port) if src_port else None,
                        dst_port=int(dst_port) if dst_port else None,
                        proto=str(proto) if proto else None
                    )
                    logger.info(f"Network RF detection: {detection['label']} ({detection['severity']})")
        
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
