"""
Analytical-Intelligence v1 - Pydantic Schemas

Shared request/response models used by routers and OpenAPI documentation.
All datetimes stored in DB are UTC; the UI converts to local timezone for display.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


# =====================================================
# Shared / Error
# =====================================================

class ErrorResponse(BaseModel):
    """Standardised error envelope returned by all API endpoints."""
    detail: str = Field(..., description="Human-readable error message")

    model_config = {
        "json_schema_extra": {
            "examples": [{"detail": "Invalid or missing API key"}]
        }
    }


# =====================================================
# Auth Event Schemas (Ingestion)
# =====================================================

class AuthEventPayload(BaseModel):
    """Payload for auth.log event ingestion."""
    device_id: str = Field(..., description="Unique sensor / device identifier")
    hostname: str = Field(..., description="Hostname of the reporting device")
    device_ip: str = Field(..., description="IP address of the device")
    line: str = Field(..., description="Raw auth.log line to analyse")
    timestamp: Optional[str] = Field(
        None, description="ISO-8601 timestamp; defaults to server UTC if omitted"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "device_id": "sensor-01",
                    "hostname": "ubuntu-gw",
                    "device_ip": "192.168.1.10",
                    "line": "Feb 14 09:00:01 ubuntu-gw sshd[12345]: Failed password for root from 10.0.0.5 port 54321 ssh2",
                    "timestamp": "2026-02-14T09:00:01Z"
                }
            ]
        }
    }


# =====================================================
# Flow Event Schemas
# =====================================================

class FlowData(BaseModel):
    """Network flow data from NFStream."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int = Field(..., description="IANA protocol number (6=TCP, 17=UDP)")
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


class FlowEventPayload(BaseModel):
    """Payload for flow event ingestion."""
    device_id: str
    hostname: str
    device_ip: str
    flow: Dict[str, Any]
    timestamp: Optional[str] = None


# =====================================================
# Suricata Alert Schemas (Ingestion)
# =====================================================

class SuricataAlertData(BaseModel):
    """Suricata alert signature data."""
    signature: str
    category: str = "Unknown"
    severity: int = 3
    action: str = "allowed"
    gid: int = 1
    sid: int = 0
    rev: int = 1
    metadata: Optional[Dict[str, Any]] = None


class SuricataAlertPayload(BaseModel):
    """Payload for Suricata alert ingestion."""
    device_id: str = Field(..., description="Unique sensor / device identifier")
    hostname: str = Field(..., description="Hostname of the reporting device")
    device_ip: str = Field(..., description="IP address of the device")
    timestamp: Optional[str] = Field(
        None, description="ISO-8601 timestamp; defaults to server UTC if omitted"
    )
    alert: Dict[str, Any] = Field(..., description="Alert signature data (signature, sid, category, severity, action)")
    raw: Optional[Dict[str, Any]] = Field(
        None, description="Raw event fields (src_ip, dest_ip, src_port, dest_port, proto, flow_id)"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "device_id": "sensor-01",
                    "hostname": "ubuntu-gw",
                    "device_ip": "192.168.1.10",
                    "timestamp": "2026-02-14T09:05:00Z",
                    "alert": {
                        "signature": "AI DDoS: SYN Flood Detected",
                        "category": "DDoS",
                        "severity": 1,
                        "action": "allowed",
                        "gid": 1,
                        "sid": 1000001,
                        "rev": 1
                    },
                    "raw": {
                        "src_ip": "10.0.0.50",
                        "dest_ip": "192.168.1.10",
                        "src_port": 0,
                        "dest_port": 80,
                        "proto": "TCP",
                        "flow_id": 123456789
                    }
                }
            ]
        }
    }


# =====================================================
# API Response Schemas
# =====================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field("ok", description="Service status")
    timestamp: str = Field(..., description="Current server time (UTC, ISO-8601)")
    version: str = Field("1.0.0", description="API version")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"status": "ok", "timestamp": "2026-02-14T06:12:21Z", "version": "1.0.0"}
            ]
        }
    }


class IngestResponse(BaseModel):
    """Response for ingestion endpoints."""
    status: str = Field("accepted", description="Processing result: accepted | rejected")
    event_id: Optional[int] = Field(None, description="Stored raw event ID")
    detection_id: Optional[int] = Field(None, description="Generated detection ID (if threat detected)")
    message: Optional[str] = Field(None, description="Human-readable status message")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": "accepted",
                    "event_id": 42,
                    "detection_id": 7,
                    "message": "Auth event processed"
                }
            ]
        }
    }


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


# =====================================================
# Device Schemas
# =====================================================

class DeviceSummaryItem(BaseModel):
    """Single device entry returned by the devices list endpoint."""
    device_id: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    last_seen: Optional[str] = None
    status: str = Field(..., description="online | offline")
    approval_status: str = Field(..., description="allowed | pending | blocked")
    blocked_reason: Optional[str] = None
    alerts_count_24h: int = 0
    alerts_count_1h: int = 0
    last_alert_ts: Optional[str] = None


class DeviceDetailResponse(BaseModel):
    """Detailed device info with recent alerts and label stats."""
    device: Dict[str, Any]
    recent_alerts: List[Dict[str, Any]]
    label_stats: List[Dict[str, Any]]
    alerts_count_24h: int
    alerts_count_1h: int
    alerts_total: int


# =====================================================
# Incident Schemas
# =====================================================

class IncidentLogResponse(BaseModel):
    """Response for the incident raw-log drilldown endpoint."""
    logs: List[Dict[str, Any]] = Field(..., description="Individual log entries")
    count: int = Field(..., description="Number of logs returned")
    total_count: Optional[int] = Field(None, description="Total matching logs (Suricata only)")
    source: str = Field(..., description="Data source: raw_events | detections")


# =====================================================
# Dashboard Analytics Schema
# =====================================================

class _TimeseriesData(BaseModel):
    labels: List[str]
    values: List[int]

class _LabelValueData(BaseModel):
    labels: List[str]
    values: List[int]

class _AnalyticsSummary(BaseModel):
    total_24h: int = 0
    high_critical_24h: int = 0
    unique_devices: int = 0
    unique_attackers: int = 0
    total_5m: int = 0
    high_critical_5m: int = 0
    intensity: float = 0

class DashboardAnalyticsResponse(BaseModel):
    """Comprehensive dashboard analytics for chart visuals."""
    timeseries: _TimeseriesData
    severity: _LabelValueData
    top_labels: _LabelValueData
    top_attackers: _LabelValueData
    by_device: _LabelValueData
    summary: _AnalyticsSummary
    window: Optional[str] = None


# =====================================================
# Models Health Schema
# =====================================================

class _SingleModelStatus(BaseModel):
    loaded: bool
    tokens: Optional[int] = None
    window_size: Optional[int] = None
    threshold: Optional[float] = None
    fail_threshold: Optional[int] = None
    time_window_sec: Optional[int] = None
    status: Optional[str] = None

class ModelsHealthResponse(BaseModel):
    """ML models health status."""
    models: Dict[str, _SingleModelStatus]
    network_ml_detector: Dict[str, Any]


# =====================================================
# Reports
# =====================================================

class ReportExportError(BaseModel):
    """Returned when export parameters are invalid."""
    error: str

