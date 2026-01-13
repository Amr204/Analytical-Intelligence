"""
Analytical-Intelligence v1 - Pydantic Schemas
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


# =====================================================
# Auth Event Schemas
# =====================================================

class AuthEventPayload(BaseModel):
    """Payload for auth.log event ingestion."""
    device_id: str
    hostname: str
    device_ip: str
    line: str
    timestamp: Optional[str] = None


# =====================================================
# Suricata Event Schemas
# =====================================================

class SuricataAlert(BaseModel):
    """Suricata alert structure."""
    signature_id: Optional[int] = None
    signature: str
    category: Optional[str] = None
    severity: Optional[int] = None
    action: Optional[str] = None


class SuricataEvent(BaseModel):
    """Suricata eve.json event structure."""
    event_type: str
    alert: Optional[SuricataAlert] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None


class SuricataEventPayload(BaseModel):
    """Payload for Suricata event ingestion."""
    device_id: str
    hostname: str
    device_ip: str
    event: Dict[str, Any]
    timestamp: Optional[str] = None


# =====================================================
# Flow Event Schemas
# =====================================================

class FlowData(BaseModel):
    """Network flow data from NFStream."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP
    bidirectional_duration_ms: Optional[int] = 0
    bidirectional_packets: Optional[int] = 0
    bidirectional_bytes: Optional[int] = 0
    src2dst_packets: Optional[int] = 0
    src2dst_bytes: Optional[int] = 0
    dst2src_packets: Optional[int] = 0
    dst2src_bytes: Optional[int] = 0
    bidirectional_mean_ps: Optional[float] = 0
    bidirectional_stddev_ps: Optional[float] = 0
    bidirectional_max_ps: Optional[int] = 0
    bidirectional_min_ps: Optional[int] = 0
    src2dst_mean_ps: Optional[float] = 0
    dst2src_mean_ps: Optional[float] = 0
    # Additional NFStream fields can be added here


class FlowEventPayload(BaseModel):
    """Payload for flow event ingestion."""
    device_id: str
    hostname: str
    device_ip: str
    flow: Dict[str, Any]
    timestamp: Optional[str] = None


# =====================================================
# API Response Schemas
# =====================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    timestamp: str
    version: str = "1.0.0"


class IngestResponse(BaseModel):
    """Response for ingestion endpoints."""
    status: str = "accepted"
    event_id: Optional[int] = None
    detection_id: Optional[int] = None
    message: Optional[str] = None


class StatsResponse(BaseModel):
    """Dashboard statistics response."""
    total_events: int
    total_detections: int
    total_devices: int
    detections_24h: int
    events_by_type: Dict[str, int]
    detections_by_model: Dict[str, int]
    detections_by_severity: Dict[str, int]


class DetectionItem(BaseModel):
    """Detection item for API responses."""
    id: int
    ts: str
    device_id: Optional[str]
    model_name: str
    label: str
    score: float
    severity: str
    details: Dict[str, Any]


class EventItem(BaseModel):
    """Raw event item for API responses."""
    id: int
    ts: str
    device_id: Optional[str]
    event_type: str
    payload: Dict[str, Any]
