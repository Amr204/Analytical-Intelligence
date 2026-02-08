"""
Analytical-Intelligence v1 - Database Layer
"""

from datetime import datetime, timedelta
from typing import Optional, List, Any, Dict
import logging
import json

from sqlalchemy import Column, String, BigInteger, Text, Float, DateTime, Boolean, create_engine, text
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
    # Device approval workflow
    approval_status: Mapped[str] = mapped_column(String, nullable=False, default='pending')
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    blocked_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)


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


class User(Base):
    """User model for UI authentication only."""
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class UserLoginState(Base):
    """User login state for lockout tracking."""
    __tablename__ = "user_login_state"
    
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    failed_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    lock_level: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)  # 0=none, 1=5min, 2=1h
    lock_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


async def ensure_schema() -> None:
    """
    Ensure database schema is up to date with idempotent DDL.
    Called once on app startup via lifespan handler.
    Note: asyncpg doesn't allow multiple statements in one execute(),
    so we run each migration statement separately.
    """
    async with engine.begin() as conn:
        # Add new columns to devices table if they don't exist
        # Run each statement separately (asyncpg limitation)
        await conn.execute(text(
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'pending'"
        ))
        await conn.execute(text(
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ NULL"
        ))
        await conn.execute(text(
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS approved_by TEXT NULL"
        ))
        await conn.execute(text(
            "ALTER TABLE devices ADD COLUMN IF NOT EXISTS blocked_reason TEXT NULL"
        ))
        
        # Create users table if not exists
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ NULL
            )
        """))
        
        # Create user_login_state table if not exists
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS user_login_state (
                user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                failed_count INT NOT NULL DEFAULT 0,
                lock_level INT NOT NULL DEFAULT 0,
                lock_until TIMESTAMPTZ NULL,
                last_failed TIMESTAMPTZ NULL,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """))
        
        # Create indexes separately
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_devices_approval_status ON devices(approval_status)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"
        ))
        
        # Backward compatibility: set existing devices (with NULL approval_status) to 'allowed'
        await conn.execute(text(
            "UPDATE devices SET approval_status = 'allowed' WHERE approval_status IS NULL OR approval_status = ''"
        ))
        
        logger.info("Database schema migration completed")


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
    """
    Upsert device and update last_seen timestamp.
    On first insert: approval_status='pending'.
    On conflict: NEVER overwrite approval_status (preserve admin decision).
    """
    await session.execute(
        text("""
            INSERT INTO devices (device_id, hostname, ip, created_at, last_seen, approval_status)
            VALUES (:device_id, :hostname, NULLIF(:ip, ''), NOW(), NOW(), 'pending')
            ON CONFLICT (device_id) DO UPDATE
            SET
              hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
              ip = COALESCE(EXCLUDED.ip, devices.ip),
              last_seen = NOW()
        """),
        {"device_id": device_id, "hostname": hostname, "ip": ip or ""}
    )


async def get_device_approval_status(session: AsyncSession, device_id: str) -> Optional[str]:
    """Get the approval status of a device."""
    result = await session.execute(
        text("SELECT approval_status FROM devices WHERE device_id = :device_id"),
        {"device_id": device_id}
    )
    row = result.first()
    return row[0] if row else None


async def set_device_approval_status(
    session: AsyncSession,
    device_id: str,
    status: str,
    approved_by: str | None = None,
    reason: str | None = None
) -> bool:
    """
    Set the approval status of a device.
    status: 'allowed', 'blocked', or 'pending'
    Returns True if device was found and updated.
    """
    if status not in ('allowed', 'blocked', 'pending'):
        raise ValueError(f"Invalid status: {status}")
    
    if status == 'allowed':
        result = await session.execute(
            text("""
                UPDATE devices 
                SET approval_status = :status,
                    approved_at = NOW(),
                    approved_by = :approved_by,
                    blocked_reason = NULL
                WHERE device_id = :device_id
            """),
            {"device_id": device_id, "status": status, "approved_by": approved_by}
        )
    elif status == 'blocked':
        result = await session.execute(
            text("""
                UPDATE devices 
                SET approval_status = :status,
                    approved_at = NULL,
                    approved_by = NULL,
                    blocked_reason = :reason
                WHERE device_id = :device_id
            """),
            {"device_id": device_id, "status": status, "reason": reason}
        )
    else:  # pending
        result = await session.execute(
            text("""
                UPDATE devices 
                SET approval_status = :status,
                    approved_at = NULL,
                    approved_by = NULL,
                    blocked_reason = NULL
                WHERE device_id = :device_id
            """),
            {"device_id": device_id, "status": status}
        )
    
    await session.commit()
    return result.rowcount > 0


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
    - approval_status, blocked_reason
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
                stats.last_alert_ts,
                d.approval_status,
                d.blocked_reason
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
            "status": status,
            "approval_status": row[10] or 'pending',
            "blocked_reason": row[11]
        })
    
    return devices


async def get_device_detail(session: AsyncSession, device_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific device.
    Returns:
    - device profile fields (including approval status)
    - recent alerts (limit 50)
    - alert stats by label in last 24h
    """
    # Get device info
    result = await session.execute(
        text("""
            SELECT device_id, hostname, ip, last_seen, created_at, os, role, tags,
                   approval_status, approved_at, approved_by, blocked_reason
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
        "status": status,
        "approval_status": row[8] or 'pending',
        "approved_at": row[9].isoformat() if row[9] else None,
        "approved_by": row[10],
        "blocked_reason": row[11]
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


# =====================================================
# Dashboard Analytics Functions
# =====================================================

async def get_dashboard_analytics(session: AsyncSession, window_hours: int = 24) -> Dict[str, Any]:
    """
    Get comprehensive dashboard analytics for the specified time window.
    
    Returns aggregated data for 5 chart visuals + summary statistics:
    - V1: Detections Over Time (hourly buckets)
    - V2: Severity Breakdown
    - V3: Top Attack Types (labels)
    - V4: Top Attacker IPs
    - V5: Alerts by Device
    - Summary: totals and threat intensity
    
    All queries use proper parameterization and efficient GROUP BY aggregation.
    """
    analytics = {}
    now = datetime.utcnow()
    
    # Build interval string for PostgreSQL (safe - validated integer)
    interval_str = f"{int(window_hours)} hours"
    
    # ─────────────────────────────────────────────────────────────
    # V1: Timeseries - Detections per hour
    # ─────────────────────────────────────────────────────────────
    result = await session.execute(
        text(f"""
            SELECT 
                date_trunc('hour', ts) AS hour_bucket,
                COUNT(*) AS detection_count
            FROM detections
            WHERE ts >= NOW() - INTERVAL '{interval_str}'
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
        """)
    )
    rows = result.fetchall()
    
    # Build complete timeline with zero-fills for missing hours
    hour_data = {}
    for row in rows:
        bucket = row[0]
        if bucket:
            hour_data[bucket.replace(tzinfo=None)] = row[1]
    
    timeseries_labels = []
    timeseries_values = []
    for i in range(window_hours, 0, -1):
        hour = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=i)
        timeseries_labels.append(hour.strftime('%H:%M'))
        timeseries_values.append(hour_data.get(hour, 0))
    
    analytics["timeseries"] = {
        "labels": timeseries_labels,
        "values": timeseries_values
    }
    
    # ─────────────────────────────────────────────────────────────
    # V2: Severity Breakdown
    # ─────────────────────────────────────────────────────────────
    result = await session.execute(
        text(f"""
            SELECT 
                severity,
                COUNT(*) AS detection_count
            FROM detections
            WHERE ts >= NOW() - INTERVAL '{interval_str}'
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
        """)
    )
    rows = result.fetchall()
    analytics["severity"] = {
        "labels": [row[0] for row in rows] if rows else [],
        "values": [row[1] for row in rows] if rows else []
    }
    
    # ─────────────────────────────────────────────────────────────
    # V3: Top Attack Types (Top 8 labels by count)
    # ─────────────────────────────────────────────────────────────
    result = await session.execute(
        text(f"""
            SELECT 
                label,
                COUNT(*) AS detection_count
            FROM detections
            WHERE ts >= NOW() - INTERVAL '{interval_str}'
              AND label IS NOT NULL
            GROUP BY label
            ORDER BY detection_count DESC
            LIMIT 8
        """)
    )
    rows = result.fetchall()
    analytics["top_labels"] = {
        "labels": [row[0][:35] if row[0] else 'Unknown' for row in rows],
        "values": [row[1] for row in rows]
    }
    
    # ─────────────────────────────────────────────────────────────
    # V4: Top Attacker IPs (Top 8 src_ip, exclude null/empty)
    # ─────────────────────────────────────────────────────────────
    result = await session.execute(
        text(f"""
            SELECT 
                src_ip,
                COUNT(*) AS attack_count
            FROM detections
            WHERE ts >= NOW() - INTERVAL '{interval_str}'
              AND src_ip IS NOT NULL 
              AND src_ip != ''
              AND src_ip != '0.0.0.0'
            GROUP BY src_ip
            ORDER BY attack_count DESC
            LIMIT 8
        """)
    )
    rows = result.fetchall()
    analytics["top_attackers"] = {
        "labels": [row[0] for row in rows] if rows else [],
        "values": [row[1] for row in rows] if rows else []
    }
    
    # ─────────────────────────────────────────────────────────────
    # V5: Alerts by Device (Top 8 devices)
    # ─────────────────────────────────────────────────────────────
    result = await session.execute(
        text(f"""
            SELECT 
                COALESCE(device_id, 'Unknown') AS device,
                COUNT(*) AS alert_count
            FROM detections
            WHERE ts >= NOW() - INTERVAL '{interval_str}'
            GROUP BY device_id
            ORDER BY alert_count DESC
            LIMIT 8
        """)
    )
    rows = result.fetchall()
    analytics["by_device"] = {
        "labels": [row[0] for row in rows] if rows else [],
        "values": [row[1] for row in rows] if rows else []
    }
    
    # ─────────────────────────────────────────────────────────────
    # Summary Statistics (single efficient query)
    # ─────────────────────────────────────────────────────────────
    result = await session.execute(
        text(f"""
            SELECT 
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE severity IN ('HIGH', 'CRITICAL')) AS high_critical,
                COUNT(DISTINCT device_id) AS unique_devices,
                COUNT(DISTINCT src_ip) FILTER (WHERE src_ip IS NOT NULL AND src_ip != '') AS unique_attackers
            FROM detections
            WHERE ts >= NOW() - INTERVAL '{interval_str}'
        """)
    )
    row = result.first()
    total_window = row[0] if row else 0
    high_critical_window = row[1] if row else 0
    unique_devices = row[2] if row else 0
    unique_attackers = row[3] if row else 0
    
    # Recent activity (5-minute window) for threat intensity
    result = await session.execute(
        text("""
            SELECT 
                COUNT(*) AS total_5m,
                COUNT(*) FILTER (WHERE severity IN ('HIGH', 'CRITICAL')) AS high_critical_5m
            FROM detections
            WHERE ts >= NOW() - INTERVAL '5 minutes'
        """)
    )
    row = result.first()
    total_5m = row[0] if row else 0
    high_critical_5m = row[1] if row else 0
    
    # Threat intensity formula: weighted score clamped 0-100
    # High/Critical events have 12x weight, all events have 2x weight
    intensity = min(100, max(0, (high_critical_5m * 12) + (total_5m * 2)))
    
    analytics["summary"] = {
        "total_24h": total_window,
        "high_critical_24h": high_critical_window,
        "unique_devices": unique_devices,
        "unique_attackers": unique_attackers,
        "total_5m": total_5m,
        "high_critical_5m": high_critical_5m,
        "intensity": intensity
    }
    
    return analytics
