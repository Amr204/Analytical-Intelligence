"""
Mini-SIEM v1 - Database Layer
"""

from datetime import datetime
from typing import Optional, List, Any
from sqlalchemy import Column, String, BigInteger, Text, Float, DateTime, create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import INET, JSONB
import json

from app.config import settings


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
    ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Store as string for simplicity
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class RawEvent(Base):
    """Raw event model."""
    __tablename__ = "raw_events"
    
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)  # 'auth', 'flow', 'suricata'
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)


class Detection(Base):
    """Detection model."""
    __tablename__ = "detections"
    
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    raw_event_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    model_name: Mapped[str] = mapped_column(String, nullable=False)  # 'ssh_lstm', 'network_ml', 'suricata'
    label: Mapped[str] = mapped_column(String, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)


async def get_session() -> AsyncSession:
    """Get a database session."""
    async with async_session_factory() as session:
        yield session


async def ensure_device(session: AsyncSession, device_id: str, hostname: str = None, ip: str = None) -> Device:
    """Ensure a device exists in the database."""
    result = await session.execute(
        text("SELECT device_id FROM devices WHERE device_id = :device_id"),
        {"device_id": device_id}
    )
    existing = result.fetchone()
    
    if not existing:
        await session.execute(
            text("""
                INSERT INTO devices (device_id, hostname, ip) 
                VALUES (:device_id, :hostname, :ip)
                ON CONFLICT (device_id) DO UPDATE SET hostname = :hostname, ip = :ip
            """),
            {"device_id": device_id, "hostname": hostname, "ip": ip}
        )
        await session.commit()


async def insert_raw_event(
    session: AsyncSession,
    ts: datetime,
    device_id: str,
    event_type: str,
    payload: dict
) -> int:
    """Insert a raw event and return its ID."""
    result = await session.execute(
        text("""
            INSERT INTO raw_events (ts, device_id, event_type, payload)
            VALUES (:ts, :device_id, :event_type, :payload)
            RETURNING id
        """),
        {
            "ts": ts,
            "device_id": device_id,
            "event_type": event_type,
            "payload": json.dumps(payload)
        }
    )
    await session.commit()
    row = result.fetchone()
    return row[0] if row else None


async def insert_detection(
    session: AsyncSession,
    ts: datetime,
    device_id: str,
    raw_event_id: int,
    model_name: str,
    label: str,
    score: float,
    severity: str,
    details: dict
) -> int:
    """Insert a detection and return its ID."""
    result = await session.execute(
        text("""
            INSERT INTO detections (ts, device_id, raw_event_id, model_name, label, score, severity, details)
            VALUES (:ts, :device_id, :raw_event_id, :model_name, :label, :score, :severity, :details)
            RETURNING id
        """),
        {
            "ts": ts,
            "device_id": device_id,
            "raw_event_id": raw_event_id,
            "model_name": model_name,
            "label": label,
            "score": score,
            "severity": severity,
            "details": json.dumps(details)
        }
    )
    await session.commit()
    row = result.fetchone()
    return row[0] if row else None


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
    """Get recent detections."""
    result = await session.execute(
        text("""
            SELECT id, ts, device_id, model_name, label, score, severity, details
            FROM detections
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
            "model_name": row[3],
            "label": row[4],
            "score": row[5],
            "severity": row[6],
            "details": row[7] if isinstance(row[7], dict) else json.loads(row[7]) if row[7] else {}
        }
        for row in rows
    ]


async def get_detections_filtered(
    session: AsyncSession,
    severity: str = None,
    model_name: str = None,
    label: str = None,
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
