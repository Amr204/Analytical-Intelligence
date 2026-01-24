"""
Analytical-Intelligence v1 - Database Layer
"""

from datetime import datetime, timedelta
from typing import Optional, List, Any, Dict
import logging
import json

from sqlalchemy import Column, String, BigInteger, Text, Float, DateTime, create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import INET, JSONB

from app.config import settings

logger = logging.getLogger(__name__)

# Device online threshold (minutes) - devices seen within this window are "online"
DEVICE_ONLINE_THRESHOLD_MINUTES = 10


# Async engine
engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=10,
    max_overflow=20,
)

# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for ORM models."""
    pass


class Device(Base):
    """Device model."""
    __tablename__ = "devices"
    
    device_id: Mapped[str] = mapped_column(String, primary_key=True)
    hostname: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    # Optional metadata
    os: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class RawEvent(Base):
    """Raw event model."""
    __tablename__ = "raw_events"
    
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)  # 'auth', 'flow'
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)


class Detection(Base):
    """Detection model."""
    __tablename__ = "detections"
    
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    raw_event_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    model_name: Mapped[str] = mapped_column(String, nullable=False)  # 'ssh_lstm', 'network_rf'
    label: Mapped[str] = mapped_column(String, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    
    # Deduplication and Traceability fields
    occurrences: Mapped[int] = mapped_column(BigInteger, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Network fields (for dedup optimization and queries)
    src_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    proto: Mapped[Optional[str]] = mapped_column(String, nullable=True)


async def get_session() -> AsyncSession:
    """Get a database session."""
    async with async_session_factory() as session:
        yield session


async def ensure_device(
    session: AsyncSession,
    device_id: str,
    hostname: str | None = None,
    ip: str | None = None
) -> None:
    """Upsert device and update last_seen timestamp."""
    await session.execute(
        text("""
            INSERT INTO devices (device_id, hostname, ip, created_at, last_seen)
            VALUES (:device_id, :hostname, NULLIF(:ip, ''), NOW(), NOW())
            ON CONFLICT (device_id) DO UPDATE
            SET
              hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
              ip = COALESCE(EXCLUDED.ip, devices.ip),
              last_seen = NOW()
        """),
        {"device_id": device_id, "hostname": hostname, "ip": ip or ""}
    )


async def insert_raw_event(
    session: AsyncSession,
    ts: datetime,
    device_id: str,
    event_type: str,
    payload: dict
) -> Optional[int]:
    """Insert a raw event and return its ID using SQLAlchemy ORM."""
    try:
        raw_event = RawEvent(
            ts=ts,
            device_id=device_id,
            event_type=event_type,
            payload=payload
        )
        session.add(raw_event)
        await session.flush()
        return raw_event.id
    except Exception as e:
        logger.error(f"Failed to insert raw_event: {e}")
        raise


async def insert_detection(
    session: AsyncSession,
    ts: datetime,
    device_id: str,
    raw_event_id: int,
    model_name: str,
    label: str,
    score: float,
    severity: str,
    details: dict,
    **kwargs
) -> Optional[int]:
    """Insert a detection and return its ID using SQLAlchemy ORM."""
    try:
        detection = Detection(
            ts=ts,
            device_id=device_id,
            raw_event_id=raw_event_id,
            model_name=model_name,
            label=label,
            score=score,
            severity=severity,
            details=details or {},
            **kwargs
        )
        session.add(detection)
        await session.flush()
        return detection.id
    except Exception as e:
        logger.error(f"Failed to insert detection: {e}")
        raise


# =====================================================
# Device Query Functions
# =====================================================

async def get_devices_summary(session: AsyncSession) -> List[Dict[str, Any]]:
    """
    Get summary of all devices with alert counts.
    Returns list of devices with:
    - device_id, hostname, ip, last_seen
    - alerts_count_24h, alerts_count_1h
    - last_alert_ts
    - status (online/offline)
    """
    result = await session.execute(
        text("""
            SELECT 
                d.device_id,
                d.hostname,
                d.ip,
                d.last_seen,
                d.created_at,
                d.os,
                d.role,
                COALESCE(stats.alerts_24h, 0) as alerts_count_24h,
                COALESCE(stats.alerts_1h, 0) as alerts_count_1h,
                stats.last_alert_ts
            FROM devices d
            LEFT JOIN (
                SELECT 
                    device_id,
                    COUNT(*) FILTER (WHERE ts > NOW() - INTERVAL '24 hours') as alerts_24h,
                    COUNT(*) FILTER (WHERE ts > NOW() - INTERVAL '1 hour') as alerts_1h,
                    MAX(ts) as last_alert_ts
                FROM detections
                GROUP BY device_id
            ) stats ON d.device_id = stats.device_id
            ORDER BY d.last_seen DESC
        """)
    )
    rows = result.fetchall()
    
    now = datetime.utcnow()
    threshold = timedelta(minutes=DEVICE_ONLINE_THRESHOLD_MINUTES)
    
    devices = []
    for row in rows:
        last_seen = row[3]
        # Compute online status
        if last_seen and (now - last_seen.replace(tzinfo=None)) < threshold:
            status = "online"
        else:
            status = "offline"
        
        devices.append({
            "device_id": row[0],
            "hostname": row[1],
            "ip": row[2],
            "last_seen": last_seen.isoformat() if last_seen else None,
            "created_at": row[4].isoformat() if row[4] else None,
            "os": row[5],
            "role": row[6],
            "alerts_count_24h": row[7] or 0,
            "alerts_count_1h": row[8] or 0,
            "last_alert_ts": row[9].isoformat() if row[9] else None,
            "status": status
        })
    
    return devices


async def get_device_detail(session: AsyncSession, device_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific device.
    Returns:
    - device profile fields
    - recent alerts (limit 50)
    - alert stats by label in last 24h
    """
    # Get device info
    result = await session.execute(
        text("""
            SELECT device_id, hostname, ip, last_seen, created_at, os, role, tags
            FROM devices
            WHERE device_id = :device_id
        """),
        {"device_id": device_id}
    )
    row = result.first()
    
    if not row:
        return None
    
    now = datetime.utcnow()
    last_seen = row[3]
    if last_seen and (now - last_seen.replace(tzinfo=None)) < timedelta(minutes=DEVICE_ONLINE_THRESHOLD_MINUTES):
        status = "online"
    else:
        status = "offline"
    
    device = {
        "device_id": row[0],
        "hostname": row[1],
        "ip": row[2],
        "last_seen": last_seen.isoformat() if last_seen else None,
        "created_at": row[4].isoformat() if row[4] else None,
        "os": row[5],
        "role": row[6],
        "tags": row[7],
        "status": status
    }
    
    # Get recent alerts
    result = await session.execute(
        text("""
            SELECT id, ts, model_name, label, score, severity, details
            FROM detections
            WHERE device_id = :device_id
            ORDER BY ts DESC
            LIMIT 50
        """),
        {"device_id": device_id}
    )
    rows = result.fetchall()
    
    recent_alerts = [
        {
            "id": r[0],
            "ts": r[1].isoformat() if r[1] else None,
            "model_name": r[2],
            "label": r[3],
            "score": r[4],
            "severity": r[5],
            "details": r[6] if isinstance(r[6], dict) else json.loads(r[6]) if r[6] else {}
        }
        for r in rows
    ]
    
    # Get alert stats by label (last 24h)
    result = await session.execute(
        text("""
            SELECT label, COUNT(*) as count
            FROM detections
            WHERE device_id = :device_id
            AND ts > NOW() - INTERVAL '24 hours'
            GROUP BY label
            ORDER BY count DESC
        """),
        {"device_id": device_id}
    )
    rows = result.fetchall()
    
    label_stats = [{"label": r[0], "count": r[1]} for r in rows]
    
    # Get total counts
    result = await session.execute(
        text("""
            SELECT 
                COUNT(*) FILTER (WHERE ts > NOW() - INTERVAL '24 hours') as alerts_24h,
                COUNT(*) FILTER (WHERE ts > NOW() - INTERVAL '1 hour') as alerts_1h,
                COUNT(*) as alerts_total
            FROM detections
            WHERE device_id = :device_id
        """),
        {"device_id": device_id}
    )
    stats_row = result.first()
    
    return {
        "device": device,
        "recent_alerts": recent_alerts,
        "label_stats": label_stats,
        "alerts_count_24h": stats_row[0] if stats_row else 0,
        "alerts_count_1h": stats_row[1] if stats_row else 0,
        "alerts_total": stats_row[2] if stats_row else 0
    }


async def get_all_device_ids(session: AsyncSession) -> List[str]:
    """Get list of all device IDs for filter dropdowns."""
    result = await session.execute(
        text("SELECT device_id FROM devices ORDER BY device_id")
    )
    return [row[0] for row in result.fetchall()]


# =====================================================
# Stats and Query Functions
# =====================================================

async def get_stats(session: AsyncSession) -> dict:
    """Get dashboard statistics."""
    stats = {}
    
    # Total events by type
    result = await session.execute(
        text("""
            SELECT event_type, COUNT(*) as count 
            FROM raw_events 
            GROUP BY event_type
        """)
    )
    stats["events_by_type"] = {row[0]: row[1] for row in result.fetchall()}
    
    # Total detections by model
    result = await session.execute(
        text("""
            SELECT model_name, COUNT(*) as count 
            FROM detections 
            GROUP BY model_name
        """)
    )
    stats["detections_by_model"] = {row[0]: row[1] for row in result.fetchall()}
    
    # Detections by severity
    result = await session.execute(
        text("""
            SELECT severity, COUNT(*) as count 
            FROM detections 
            GROUP BY severity
        """)
    )
    stats["detections_by_severity"] = {row[0]: row[1] for row in result.fetchall()}
    
    # Recent detections (last 24h)
    result = await session.execute(
        text("""
            SELECT COUNT(*) 
            FROM detections 
            WHERE ts > NOW() - INTERVAL '24 hours'
        """)
    )
    stats["detections_24h"] = result.scalar() or 0
    
    # Total counts
    result = await session.execute(text("SELECT COUNT(*) FROM raw_events"))
    stats["total_events"] = result.scalar() or 0
    
    result = await session.execute(text("SELECT COUNT(*) FROM detections"))
    stats["total_detections"] = result.scalar() or 0
    
    result = await session.execute(text("SELECT COUNT(*) FROM devices"))
    stats["total_devices"] = result.scalar() or 0
    
    return stats


async def get_recent_detections(session: AsyncSession, limit: int = 20) -> List[dict]:
    """Get recent detections, ordered by most recent activity (last_seen or ts)."""
    result = await session.execute(
        text("""
            SELECT id, ts, device_id, model_name, label, score, severity, details, occurrences, last_seen
            FROM detections
            ORDER BY COALESCE(last_seen, ts) DESC
            LIMIT :limit
        """),
        {"limit": limit}
    )
    rows = result.fetchall()
    return [
        {
            "id": row[0],
            "ts": row[1].isoformat() if row[1] else None,
            "device_id": row[2],
            "model_name": row[3],
            "label": row[4],
            "score": row[5],
            "severity": row[6],
            "details": row[7] if isinstance(row[7], dict) else json.loads(row[7]) if row[7] else {},
            "occurrences": row[8] or 1,
            "last_seen": row[9].isoformat() if row[9] else None,
        }
        for row in rows
    ]


async def get_detections_filtered(
    session: AsyncSession,
    severity: str = None,
    model_name: str = None,
    label: str = None,
    device_id: str = None,
    last_minutes: int = None,
    limit: int = 100
) -> List[dict]:
    """Get filtered detections."""
    query = "SELECT id, ts, device_id, model_name, label, score, severity, details FROM detections WHERE 1=1"
    params = {"limit": limit}
    
    if severity:
        query += " AND severity = :severity"
        params["severity"] = severity
    
    if model_name:
        query += " AND model_name = :model_name"
        params["model_name"] = model_name
    
    if label:
        query += " AND label ILIKE :label"
        params["label"] = f"%{label}%"
    
    if device_id:
        query += " AND device_id = :device_id"
        params["device_id"] = device_id
    
    if last_minutes:
        query += f" AND ts > NOW() - INTERVAL '{int(last_minutes)} minutes'"
    
    query += " ORDER BY ts DESC LIMIT :limit"
    
    result = await session.execute(text(query), params)
    rows = result.fetchall()
    return [
        {
            "id": row[0],
            "ts": row[1].isoformat() if row[1] else None,
            "device_id": row[2],
            "model_name": row[3],
            "label": row[4],
            "score": row[5],
            "severity": row[6],
            "details": row[7] if isinstance(row[7], dict) else json.loads(row[7]) if row[7] else {}
        }
        for row in rows
    ]


async def get_raw_events(
    session: AsyncSession,
    event_type: str = None,
    limit: int = 100
) -> List[dict]:
    """Get raw events."""
    if event_type:
        result = await session.execute(
            text("""
                SELECT id, ts, device_id, event_type, payload
                FROM raw_events
                WHERE event_type = :event_type
                ORDER BY ts DESC
                LIMIT :limit
            """),
            {"event_type": event_type, "limit": limit}
        )
    else:
        result = await session.execute(
            text("""
                SELECT id, ts, device_id, event_type, payload
                FROM raw_events
                ORDER BY ts DESC
                LIMIT :limit
            """),
            {"limit": limit}
        )
    
    rows = result.fetchall()
    return [
        {
            "id": row[0],
            "ts": row[1].isoformat() if row[1] else None,
            "device_id": row[2],
            "event_type": row[3],
            "payload": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {}
        }
        for row in rows
    ]
