"""
Analytical-Intelligence v1 - Suricata Alert Ingestion
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy import text

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session, ensure_device, insert_raw_event, insert_detection, get_device_approval_status
from app.security import verify_api_key
from app.schemas import SuricataAlertPayload, IngestResponse
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


def map_severity(suricata_severity: int) -> tuple[str, float]:
    """
    Map Suricata numeric severity to string and score.
    Suricata: 1=highest, 2=medium, 3=low
    
    Returns:
        (severity_string, score)
    """
    if suricata_severity == 1:
        return ("CRITICAL", 0.95)
    elif suricata_severity == 2:
        return ("HIGH", 0.85)
    elif suricata_severity == 3:
        return ("MEDIUM", 0.70)
    else:
        return ("LOW", 0.50)


@router.post("/suricata", response_model=IngestResponse)
async def ingest_suricata_alert(
    payload: SuricataAlertPayload,
    api_key: str = Depends(verify_api_key),
    session: AsyncSession = Depends(get_session)
):
    """
    Ingest a Suricata IDS alert.
    Stores the raw event and creates a detection.
    Device must be 'allowed' to store events.
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
        
        # Ensure device exists (creates with 'pending' status if new)
        await ensure_device(session, payload.device_id, payload.hostname, payload.device_ip)
        await session.commit()
        
        # Check device approval status
        approval_status = await get_device_approval_status(session, payload.device_id)
        if approval_status != 'allowed':
            # Reject but return 200 to prevent sensor retries
            message = "Device pending approval" if approval_status == 'pending' else "Device blocked"
            logger.info(f"Suricata event rejected: device={payload.device_id}, status={approval_status}")
            return IngestResponse(
                status="rejected",
                event_id=None,
                detection_id=None,
                message=message
            )
        
        # Extract alert data (only for allowed devices)
        alert = payload.alert
        raw = payload.raw or {}
        
        # Build full raw payload for storage
        full_raw = {
            "timestamp": payload.timestamp,
            "alert": alert,
            **raw
        }
        
        # Store raw event
        event_id = await insert_raw_event(
            session,
            ts=ts,
            device_id=payload.device_id,
            event_type="suricata",
            payload=full_raw
        )
        
        # Extract fields for detection
        signature = alert.get("signature", f"sid:{alert.get('sid', 'unknown')}")
        category = alert.get("category", "Unknown")
        suricata_severity = alert.get("severity", 3)
        sid = alert.get("sid", 0)
        gid = alert.get("gid", 1)
        rev = alert.get("rev", 1)
        action = alert.get("action", "allowed")
        
        # Network fields from raw
        src_ip = raw.get("src_ip", "")
        dst_ip = raw.get("dest_ip", raw.get("dst_ip", ""))
        src_port = raw.get("src_port", 0)
        dst_port = raw.get("dest_port", raw.get("dst_port", 0))
        proto = raw.get("proto", "")
        flow_id = raw.get("flow_id")
        
        # Map severity
        severity, score = map_severity(suricata_severity)
        
        # Build detection details
        details = {
            "sid": sid,
            "gid": gid,
            "rev": rev,
            "category": category,
            "signature": signature,
            "action": action,
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "suricata_severity": suricata_severity,
        }
        
        # --- Deduplication Logic ---
        # Check for existing detection with same signature and flow tuple
        dedup_window = getattr(settings, 'suricata_dedup_window_seconds', 10)
        dedup_cutoff = ts - timedelta(seconds=dedup_window)
        
        dedup_query = text("""
            SELECT id, occurrences 
            FROM detections 
            WHERE model_name = 'suricata'
            AND label = :label
            AND ts > :cutoff
            AND src_ip = :src_ip
            AND dst_ip = :dst_ip
            AND dst_port = :dst_port
            ORDER BY ts DESC 
            LIMIT 1
        """)
        
        result = await session.execute(dedup_query, {
            "label": signature,
            "cutoff": dedup_cutoff,
            "src_ip": str(src_ip) if src_ip else "",
            "dst_ip": str(dst_ip) if dst_ip else "",
            "dst_port": int(dst_port) if dst_port else 0
        })
        existing = result.first()
        
        detection_id = None
        
        if existing:
            # Update existing detection
            detection_id = existing[0]
            new_occurrences = (existing[1] or 1) + 1
            await session.execute(text("""
                UPDATE detections 
                SET occurrences = :occurrences, last_seen = :ts, ts = :ts
                WHERE id = :id
            """), {"occurrences": new_occurrences, "ts": ts, "id": detection_id})
            logger.info(f"Suricata detection DEDUP: {signature} (x{new_occurrences})")
        else:
            # Insert new detection
            detection_id = await insert_detection(
                session,
                ts=ts,
                device_id=payload.device_id,
                raw_event_id=event_id,
                model_name="suricata",
                label=signature,
                score=score,
                severity=severity,
                details=details,
                occurrences=1,
                first_seen=ts,
                last_seen=ts,
                src_ip=str(src_ip) if src_ip else None,
                dst_ip=str(dst_ip) if dst_ip else None,
                src_port=int(src_port) if src_port else None,
                dst_port=int(dst_port) if dst_port else None,
                proto=str(proto) if proto else None
            )
            logger.info(f"Suricata detection: {signature} ({severity})")
            
            # Enqueue Telegram alert (non-blocking)
            from app.notifications import get_notification_bus
            bus = get_notification_bus()
            if bus:
                bus.enqueue_alert({
                    "detection_id": detection_id,
                    "timestamp": ts.isoformat() + "Z",
                    "device_id": payload.device_id,
                    "model_name": "suricata",
                    "label": signature,
                    "score": score,
                    "severity": severity,
                    "src_ip": str(src_ip) if src_ip else None,
                    "dst_ip": str(dst_ip) if dst_ip else None,
                    "src_port": int(src_port) if src_port else None,
                    "dst_port": int(dst_port) if dst_port else None,
                    "protocol": str(proto) if proto else None,
                    "reason": f"Suricata: {category}",
                })
        
        await session.commit()

        return IngestResponse(
            status="accepted",
            event_id=event_id,
            detection_id=detection_id,
            message="Suricata alert processed"
        )

    except Exception as e:
        await session.rollback()
        logger.error(f"Suricata ingestion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
