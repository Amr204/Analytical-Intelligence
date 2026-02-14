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

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])


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


def is_ai_local_rule(signature: str, sid: int) -> bool:
    """
    Check if alert is from our local AI rules (not ET/external noise).
    
    Accept if:
    - Signature starts with "AI " (our naming convention)
    - OR SID is in the local range (1000000-1009999)
    """
    if signature.startswith("AI "):
        return True
    if settings.suricata_local_sid_min <= sid <= settings.suricata_local_sid_max:
        return True
    return False


def is_ddos_rule(signature: str) -> bool:
    """
    Check if this is a DDoS rule (distributed attack, destination-based).
    For DDoS rules, we ignore src_ip in dedup key to aggregate multi-source attacks.
    """
    return "AI DDoS:" in signature


def compute_bucket_window(ts: datetime, window_minutes: int) -> tuple[datetime, datetime]:
    """
    Compute the fixed time bucket for a given timestamp.
    
    Args:
        ts: Alert timestamp
        window_minutes: Bucket size in minutes (e.g., 5)
    
    Returns:
        (bucket_start, bucket_end) - both are timezone-aware if ts is
    """
    # Truncate to minute boundary
    bucket_start = ts.replace(second=0, microsecond=0)
    # Align to window boundary (e.g., 5-min buckets: 00:00, 00:05, 00:10, ...)
    minutes_since_midnight = bucket_start.hour * 60 + bucket_start.minute
    bucket_offset = minutes_since_midnight % window_minutes
    bucket_start = bucket_start - timedelta(minutes=bucket_offset)
    bucket_end = bucket_start + timedelta(minutes=window_minutes)
    return bucket_start, bucket_end


@router.post(
    "/suricata",
    response_model=IngestResponse,
    summary="Ingest Suricata IDS alert",
    description="Submit a Suricata alert from a sensor agent. "
                "The backend stores the raw event, maps severity, and applies "
                "bucket-based deduplication (default 5-min windows). "
                "DDoS rules ignore src_ip for multi-source aggregation. "
                "Device must have approval_status='allowed'.",
    responses={
        200: {"description": "Alert accepted or rejected (always 200 to prevent sensor retries)"},
        401: {"description": "Invalid or missing API key"},
        500: {"description": "Internal processing error"},
    },
)
async def ingest_suricata_alert(
    payload: SuricataAlertPayload,
    api_key: str = Depends(verify_api_key),
    session: AsyncSession = Depends(get_session)
):
    """
    Ingest a Suricata IDS alert.
    Stores the raw event and creates/updates a detection.
    Device must be 'allowed' to store events.
    
    Deduplication Strategy:
    - Uses fixed time-bucket windows (default 5 min) instead of sliding windows
    - A continuous attack produces one detection per bucket, not one forever-growing row
    - DDoS rules ignore src_ip (aggregate multi-source attacks)
    - Other rules include src_ip in dedup key
    - Only 'ts' is set on INSERT (first alert in bucket), not on UPDATE
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
            # Reject but return 200 to prevent sensor retries (which would just spam the logs)
            # LOG THIS CRITICAL WARNING so admin knows why alerts are missing
            message = "Device pending approval" if approval_status == 'pending' else "Device blocked"
            logger.warning(f"⛔ SURICATA ALERT REJECTED: device={payload.device_id}, status={approval_status}. Go to /devices to approve this sensor.")
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
        
        # --- Allowlist Check ---
        # Only process alerts from our local AI rules
        if not is_ai_local_rule(signature, sid):
            # Store raw event for audit but don't create detection or send Telegram
            event_id = await insert_raw_event(
                session,
                ts=ts,
                device_id=payload.device_id,
                event_type="suricata",
                payload=full_raw
            )
            await session.commit()
            logger.debug(f"Suricata event stored (non-AI rule, no detection): {signature}")
            return IngestResponse(
                status="accepted",
                event_id=event_id,
                detection_id=None,
                message="Raw event stored (external rule, no detection created)"
            )
        
        # Store raw event
        event_id = await insert_raw_event(
            session,
            ts=ts,
            device_id=payload.device_id,
            event_type="suricata",
            payload=full_raw
        )
        
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
        
        # --- Bucket-Based Deduplication ---
        rollup_minutes = settings.suricata_rollup_window_minutes
        bucket_start, bucket_end = compute_bucket_window(ts, rollup_minutes)
        
        # Determine if DDoS (ignore src_ip in dedup)
        ddos_mode = is_ddos_rule(signature)
        
        # Build dedup query based on rule type
        if ddos_mode:
            # DDoS: dedup by (device_id, label, dst_ip, dst_port, bucket)
            dedup_query = text("""
                SELECT id, occurrences 
                FROM detections 
                WHERE model_name = 'suricata'
                AND label = :label
                AND device_id = :device_id
                AND (dst_ip = :dst_ip OR (dst_ip IS NULL AND :dst_ip = ''))
                AND (dst_port = :dst_port OR (dst_port IS NULL AND :dst_port = 0))
                AND ts >= :bucket_start AND ts < :bucket_end
                ORDER BY ts DESC 
                LIMIT 1
            """)
            dedup_params = {
                "label": signature,
                "device_id": payload.device_id,
                "dst_ip": str(dst_ip) if dst_ip else "",
                "dst_port": int(dst_port) if dst_port else 0,
                "bucket_start": bucket_start,
                "bucket_end": bucket_end
            }
        else:
            # Non-DDoS: include src_ip in dedup key
            dedup_query = text("""
                SELECT id, occurrences 
                FROM detections 
                WHERE model_name = 'suricata'
                AND label = :label
                AND device_id = :device_id
                AND (src_ip = :src_ip OR (src_ip IS NULL AND :src_ip = ''))
                AND (dst_ip = :dst_ip OR (dst_ip IS NULL AND :dst_ip = ''))
                AND (dst_port = :dst_port OR (dst_port IS NULL AND :dst_port = 0))
                AND ts >= :bucket_start AND ts < :bucket_end
                ORDER BY ts DESC 
                LIMIT 1
            """)
            dedup_params = {
                "label": signature,
                "device_id": payload.device_id,
                "src_ip": str(src_ip) if src_ip else "",
                "dst_ip": str(dst_ip) if dst_ip else "",
                "dst_port": int(dst_port) if dst_port else 0,
                "bucket_start": bucket_start,
                "bucket_end": bucket_end
            }
        
        result = await session.execute(dedup_query, dedup_params)
        existing = result.first()
        
        detection_id = None
        is_new_detection = False
        
        if existing:
            # Update existing detection within same bucket
            # DO NOT update ts - keep the original first-seen timestamp for the bucket
            detection_id = existing[0]
            new_occurrences = (existing[1] or 1) + 1
            await session.execute(text("""
                UPDATE detections 
                SET occurrences = :occurrences, 
                    last_seen = :last_seen
                WHERE id = :id
            """), {"occurrences": new_occurrences, "last_seen": ts, "id": detection_id})
            logger.debug(f"Suricata detection DEDUP [{bucket_start.strftime('%H:%M')}-{bucket_end.strftime('%H:%M')}]: {signature} (x{new_occurrences})")
        else:
            # Insert new detection for this bucket
            is_new_detection = True
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
            logger.info(f"Suricata detection NEW [{bucket_start.strftime('%H:%M')}-{bucket_end.strftime('%H:%M')}]: {signature} ({severity})")
            
            # Enqueue Telegram alert ONLY for NEW detections (not dedup updates)
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
            message="Suricata alert processed" + (" (new)" if is_new_detection else " (dedup)")
        )

    except Exception as e:
        await session.rollback()
        logger.error(f"Suricata ingestion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
