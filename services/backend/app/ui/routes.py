"""
Analytical-Intelligence v1 - UI Routes
Server-rendered HTML pages using Jinja2 templates.
"""

from datetime import datetime
from typing import Optional, List
from io import StringIO, BytesIO
import csv
import json

from fastapi import APIRouter, Request, Depends, Query, Form
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import (
    get_session, 
    get_stats, 
    get_recent_detections,
    get_detections_filtered,
    get_incidents_filtered,
    get_incident_logs,
    get_suricata_incident_raw_logs,
    get_raw_events,
    get_devices_summary,
    get_device_detail,
    get_all_device_ids,
    get_dashboard_analytics,
    set_device_approval_status
)
from app.models_loader import get_models_status
from app.schemas import (
    ErrorResponse,
    StatsResponse,
    DetectionItem,
    DeviceSummaryItem,
    DeviceDetailResponse,
    DashboardAnalyticsResponse,
    ModelsHealthResponse,
    IncidentLogResponse,
    ReportExportError,
)
from app.auth import (
    get_user_by_username,
    get_user_login_state,
    verify_password,
    increment_failed_attempt,
    reset_login_state,
    update_last_login,
    is_account_locked
)

router = APIRouter()

# Templates directory
templates = Jinja2Templates(directory="app/templates")

# Add tojson filter to Jinja2 environment
templates.env.filters["tojson"] = lambda x: json.dumps(x, default=str)


def get_current_user(request: Request) -> Optional[dict]:
    """Get current logged in user from session."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return {
        "id": user_id,
        "username": request.session.get("username"),
        "full_name": request.session.get("full_name")
    }


# =====================================================
# Authentication Routes
# =====================================================

@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request, next: str = "/dashboard"):
    """Login page."""
    # If already logged in, redirect
    if request.session.get("user_id"):
        return RedirectResponse(url=next, status_code=303)
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "page_title": "Login",
        "next": next,
        "error": None
    })


@router.post("/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/dashboard"),
    session: AsyncSession = Depends(get_session)
):
    """Process login form."""
    error = None
    
    # Get user
    user = await get_user_by_username(session, username)
    
    if not user or not user["is_active"]:
        # Generic error to prevent user enumeration
        error = "Invalid credentials"
    else:
        # Check lockout
        login_state = await get_user_login_state(session, user["id"])
        locked, lock_until = is_account_locked(login_state)
        
        if locked:
            remaining = int((lock_until.replace(tzinfo=None) - datetime.utcnow()).total_seconds() / 60)
            error = f"Account locked. Try again in {remaining + 1} minute(s)."
        elif not verify_password(password, user["password_hash"]):
            # Wrong password - increment failed count
            result = await increment_failed_attempt(session, user["id"])
            if result["is_locked"]:
                error = "Account locked due to too many failed attempts. Try again later."
            else:
                error = "Invalid credentials"
        else:
            # Success - set session and reset lockout
            request.session["user_id"] = user["id"]
            request.session["username"] = user["username"]
            request.session["full_name"] = user.get("full_name") or user["username"]
            
            await reset_login_state(session, user["id"])
            await update_last_login(session, user["id"])
            
            # Validate and use next URL
            if not next or not next.startswith("/") or next.startswith("//"):
                next = "/dashboard"
            
            return RedirectResponse(url=next, status_code=303)
    
    # Show error
    return templates.TemplateResponse("login.html", {
        "request": request,
        "page_title": "Login",
        "next": next,
        "error": error
    })


@router.get("/logout", include_in_schema=False)
async def logout(request: Request):
    """Logout and clear session."""
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


# =====================================================
# Device Approval Routes  
# =====================================================

@router.post("/devices/{device_id}/allow", include_in_schema=False)
async def allow_device(
    request: Request,
    device_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Allow a device to send events."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    await set_device_approval_status(
        session, 
        device_id, 
        "allowed", 
        approved_by=user["username"]
    )
    
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/devices/{device_id}/block", include_in_schema=False)
async def block_device(
    request: Request,
    device_id: str,
    reason: str = Form(""),
    session: AsyncSession = Depends(get_session)
):
    """Block a device from sending events."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    await set_device_approval_status(
        session, 
        device_id, 
        "blocked", 
        reason=reason or None
    )
    
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/devices/{device_id}/pending", include_in_schema=False)
async def set_device_pending(
    request: Request,
    device_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Set device back to pending status."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    
    await set_device_approval_status(session, device_id, "pending")
    
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


# =====================================================
# Page Routes
# =====================================================


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home_page(request: Request):
    """Home landing page."""
    from app.config import settings
    
    social_links = {
        "telegram": settings.app_telegram_url or None,
        "github": settings.app_github_url or None,
        "discord": settings.app_discord_url or None,
        "drive": settings.app_drive_url or None,
    }
    
    return templates.TemplateResponse("home.html", {
        "request": request,
        "page_title": "Home",
        "social_links": social_links,
    })


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Dashboard page with analytics (no recent alerts)."""
    import logging
    logger = logging.getLogger(__name__)
    
    # Default empty stats
    stats = {
        "total_events": 0,
        "total_detections": 0,
        "detections_24h": 0,
        "total_devices": 0,
        "events_by_type": {},
        "detections_by_model": {},
        "detections_by_severity": {}
    }
    
    # Default empty analytics
    analytics = {
        "timeseries": {"labels": [], "values": []},
        "severity": {"labels": [], "values": []},
        "top_labels": {"labels": [], "values": []},
        "top_attackers": {"labels": [], "values": []},
        "by_device": {"labels": [], "values": []},
        "summary": {
            "total_24h": 0,
            "high_critical_24h": 0,
            "unique_devices": 0,
            "unique_attackers": 0,
            "total_5m": 0,
            "high_critical_5m": 0,
            "intensity": 0
        }
    }
    
    try:
        stats = await get_stats(session)
    except Exception as e:
        logger.error(f"Error fetching stats: {e}", exc_info=True)
    
    try:
        analytics = await get_dashboard_analytics(session)
    except Exception as e:
        logger.error(f"Error fetching analytics: {e}", exc_info=True)
    
    # Pre-serialize to JSON strings for safe template embedding
    analytics_json = json.dumps(analytics, default=str)
    stats_json = json.dumps(stats, default=str)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "analytics": analytics,
        "analytics_json": analytics_json,
        "stats_json": stats_json,
        "page_title": "Dashboard",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/alerts", response_class=HTMLResponse, include_in_schema=False)
async def alerts_page(
    request: Request,
    view: Optional[str] = Query("incidents"),  # incidents or raw
    severity: Optional[str] = Query(None),
    model_name: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    last_minutes: Optional[str] = Query(None),
    window_minutes: Optional[int] = Query(5),  # Incident grouping window
    page: Optional[int] = Query(1),
    per_page: Optional[int] = Query(25),
    session: AsyncSession = Depends(get_session)
):
    """
    Alerts/detections list page with filters and incident grouping.
    
    view=incidents: Show grouped incidents within time windows
    view=raw: Show raw detection logs with pagination
    """
    # Normalize view parameter
    view = view.lower() if view else "incidents"
    if view not in ("incidents", "raw"):
        view = "incidents"
    
    # Convert last_minutes to int, handling empty string
    last_minutes_int = int(last_minutes) if last_minutes and last_minutes.strip() else None
    
    # Clean filter values
    severity_clean = severity if severity and severity.strip() else None
    model_name_clean = model_name if model_name and model_name.strip() else None
    label_clean = label if label and label.strip() else None
    device_id_clean = device_id if device_id and device_id.strip() else None
    
    # Ensure valid pagination values
    page = max(1, page or 1)
    per_page = min(100, max(10, per_page or 25))
    window_minutes = max(1, min(60, window_minutes or 5))
    offset = (page - 1) * per_page
    
    # Build query string for pagination (preserving filters)
    def build_query_string(exclude_keys=None):
        exclude_keys = exclude_keys or []
        params = []
        if view and "view" not in exclude_keys:
            params.append(f"view={view}")
        if severity_clean and "severity" not in exclude_keys:
            params.append(f"severity={severity_clean}")
        if model_name_clean and "model_name" not in exclude_keys:
            params.append(f"model_name={model_name_clean}")
        if label_clean and "label" not in exclude_keys:
            params.append(f"label={label_clean}")
        if device_id_clean and "device_id" not in exclude_keys:
            params.append(f"device_id={device_id_clean}")
        if last_minutes_int and "last_minutes" not in exclude_keys:
            params.append(f"last_minutes={last_minutes_int}")
        if window_minutes and "window_minutes" not in exclude_keys:
            params.append(f"window_minutes={window_minutes}")
        if per_page and "per_page" not in exclude_keys:
            params.append(f"per_page={per_page}")
        return "&" + "&".join(params) if params else ""
    
    query_string = build_query_string(exclude_keys=["page"])
    
    # Fetch data based on view type
    if view == "incidents":
        incidents, total_count = await get_incidents_filtered(
            session,
            severity=severity_clean,
            model_name=model_name_clean,
            label=label_clean,
            device_id=device_id_clean,
            window_minutes=window_minutes,
            last_minutes=last_minutes_int,
            limit=per_page,
            offset=offset,
            return_total=True
        )
        detections = []
    else:  # view == "raw"
        incidents = []
        detections_raw, total_count = await get_detections_filtered(
            session,
            severity=severity_clean,
            model_name=model_name_clean,
            label=label_clean,
            device_id=device_id_clean,
            last_minutes=last_minutes_int,
            limit=per_page,
            offset=offset,
            return_total=True
        )
        # Pre-serialize details to JSON for each detection
        detections = []
        for d in detections_raw:
            details = d.get("details", {}) or {}
            det_dict = {
                "id": d.get("id"),
                "ts": str(d.get("ts", ""))[:19] if d.get("ts") else None,
                "severity": d.get("severity"),
                "model_name": d.get("model_name"),
                "label": d.get("label"),
                "device_id": d.get("device_id"),
                "score": float(d.get("score", 0) or 0),
                "details": details,
                "details_json": json.dumps(details, default=str),
                "src_ip": details.get("src_ip", ""),
                "src_port": details.get("src_port", ""),
                "dst_ip": details.get("dst_ip", ""),
                "dst_port": details.get("dst_port", ""),
            }
            detections.append(det_dict)
    
    # Calculate pagination info
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    
    pagination = {
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": total_pages,
        "query_string": query_string,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }
    
    # Get device list for filter dropdown
    device_ids = await get_all_device_ids(session)
    
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "view": view,
        "incidents": incidents,
        "detections": detections,
        "device_ids": device_ids,
        "pagination": pagination,
        "filters": {
            "severity": severity_clean,
            "model_name": model_name_clean,
            "label": label_clean,
            "device_id": device_id_clean,
            "last_minutes": last_minutes_int,
            "window_minutes": window_minutes
        },
        "page_title": "Alerts",
        "now": datetime.utcnow().isoformat()
    })


@router.get(
    "/api/v1/incidents/logs",
    tags=["Incidents"],
    summary="Get raw logs for an incident",
    description="Fetch individual detection or raw-event logs for a specific incident "
                "identified by its label, severity, model, device, and time window. "
                "Suricata incidents query the raw_events table; others query detections.",
    response_model=IncidentLogResponse,
    responses={500: {"model": ErrorResponse}},
)
async def api_incident_logs(
    label: str = Query(..., description="Incident label / signature"),
    severity: str = Query(..., description="Severity level"),
    model_name: str = Query(..., description="Detection model name (e.g. suricata, ssh_lstm)"),
    device_id: str = Query(..., description="Device identifier"),
    window_start: str = Query(..., description="ISO-8601 window start (UTC)"),
    window_end: str = Query(..., description="ISO-8601 window end (UTC)"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    dst_port: Optional[int] = Query(None, description="Filter by destination port"),
    session: AsyncSession = Depends(get_session)
):
    """
    API endpoint to fetch raw logs for a specific incident.
    
    For Suricata incidents, queries raw_events table to show all alerts.
    For other models (SSH LSTM), queries detections table.
    """
    if model_name == "suricata":
        # Suricata: query raw_events for all alerts in the window
        logs, total_count = await get_suricata_incident_raw_logs(
            session,
            device_id=device_id,
            label=label,
            window_start=window_start,
            window_end=window_end,
            dst_ip=dst_ip if dst_ip else None,
            dst_port=dst_port if dst_port else None,
            limit=200
        )
        return {
            "logs": logs, 
            "count": len(logs),
            "total_count": total_count,
            "source": "raw_events"
        }
    else:
        # SSH LSTM and other models: use existing detection logs
        logs = await get_incident_logs(
            session,
            label=label,
            severity=severity,
            model_name=model_name,
            device_id=device_id,
            window_start=window_start,
            window_end=window_end,
            dst_ip=dst_ip if dst_ip else None,
            dst_port=dst_port if dst_port else None,
            limit=100
        )
        return {"logs": logs, "count": len(logs), "source": "detections"}


@router.get("/devices", response_class=HTMLResponse, include_in_schema=False)
async def devices_page(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Devices inventory page with cards."""
    devices = await get_devices_summary(session)
    
    return templates.TemplateResponse("devices.html", {
        "request": request,
        "devices": devices,
        "page_title": "Devices",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/devices/{device_id}", response_class=HTMLResponse, include_in_schema=False)
async def device_detail_page(
    request: Request,
    device_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Device detail page with alerts and stats."""
    data = await get_device_detail(session, device_id)
    
    if not data:
        return templates.TemplateResponse("404.html", {
            "request": request,
            "message": f"Device '{device_id}' not found",
            "page_title": "Not Found"
        }, status_code=404)
    
    return templates.TemplateResponse("device_detail.html", {
        "request": request,
        "device": data["device"],
        "recent_alerts": data["recent_alerts"],
        "label_stats": data["label_stats"],
        "alerts_count_24h": data["alerts_count_24h"],
        "alerts_count_1h": data["alerts_count_1h"],
        "alerts_total": data["alerts_total"],
        "page_title": f"Device: {device_id}",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/events/auth", response_class=HTMLResponse, include_in_schema=False)
async def auth_events_page(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Raw auth events page."""
    events = await get_raw_events(session, event_type="auth", limit=100)
    
    return templates.TemplateResponse("auth_events.html", {
        "request": request,
        "events": events,
        "page_title": "Auth Events",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/events/flows", response_class=HTMLResponse, include_in_schema=False)
async def flow_events_page(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Raw flow events page."""
    events = await get_raw_events(session, event_type="flow", limit=100)
    
    return templates.TemplateResponse("flow_events.html", {
        "request": request,
        "events": events,
        "page_title": "Flow Events",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/events/suricata", response_class=HTMLResponse, include_in_schema=False)
async def suricata_events_page(
    request: Request,
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    last_minutes: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session)
):
    """Suricata IDS alerts page."""
    # Clean parameters
    severity_clean = severity if severity and severity.strip() else None
    src_ip_clean = src_ip if src_ip and src_ip.strip() else None
    dst_ip_clean = dst_ip if dst_ip and dst_ip.strip() else None
    last_minutes_int = int(last_minutes) if last_minutes and last_minutes.strip() else None
    
    # Get suricata detections
    detections = await get_detections_filtered(
        session,
        model_name="suricata",
        severity=severity_clean,
        last_minutes=last_minutes_int,
        limit=100
    )
    
    # Convert detections for template with IP extraction from details
    # Note: get_detections_filtered returns dicts, so use dict key access
    detections_list = []
    for d in detections:
        det = {
            "id": d.get("id"),
            "ts": str(d.get("ts", "")) if d.get("ts") else None,
            "severity": d.get("severity"),
            "label": d.get("label"),
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "proto": None,
            "sid": None
        }
        # Extract IPs from details if available
        details = d.get("details", {})
        if details and isinstance(details, dict):
            det["src_ip"] = details.get("src_ip")
            det["src_port"] = details.get("src_port")
            det["dst_ip"] = details.get("dest_ip") or details.get("dst_ip")
            det["dst_port"] = details.get("dest_port") or details.get("dst_port")
            det["proto"] = details.get("proto")
            det["sid"] = details.get("signature_id") or details.get("sid")
        
        # Apply IP filters if specified
        if src_ip_clean and det["src_ip"] != src_ip_clean:
            continue
        if dst_ip_clean and det["dst_ip"] != dst_ip_clean:
            continue
            
        detections_list.append(det)
    
    # Compute severity stats for 24h
    all_detections_24h = await get_detections_filtered(
        session,
        model_name="suricata",
        last_minutes=1440,  # 24 hours
        limit=10000
    )
    severity_stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    signature_counts = {}
    ip_counts = {}
    
    for d in all_detections_24h:
        sev = d.get("severity")
        if sev in severity_stats:
            severity_stats[sev] += 1
        lbl = d.get("label")
        if lbl:
            signature_counts[lbl] = signature_counts.get(lbl, 0) + 1
        # Extract src_ip from details
        details = d.get("details", {})
        if details and isinstance(details, dict):
            src = details.get("src_ip")
            if src:
                ip_counts[src] = ip_counts.get(src, 0) + 1
    
    # Top signatures
    top_signatures = [{"label": k, "count": v} for k, v in sorted(signature_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    # Top source IPs
    top_src_ips = [{"ip": k, "count": v} for k, v in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    return templates.TemplateResponse("suricata.html", {
        "request": request,
        "detections": detections_list,
        "severity_stats": severity_stats,
        "top_signatures": top_signatures,
        "top_src_ips": top_src_ips,
        "filters": {
            "severity": severity_clean,
            "src_ip": src_ip_clean,
            "dst_ip": dst_ip_clean,
            "last_minutes": last_minutes_int
        },
        "page_title": "Suricata Events",
        "now": datetime.utcnow().isoformat()
    })

@router.get("/models", response_class=HTMLResponse, include_in_schema=False)
async def models_page(request: Request):
    """ML models status page."""
    models_status = get_models_status()
    
    return templates.TemplateResponse("models.html", {
        "request": request,
        "models": models_status,
        "page_title": "Models",
        "now": datetime.utcnow().isoformat()
    })


# =====================================================
# JSON API Endpoints (documented in Swagger)
# =====================================================

@router.get(
    "/api/v1/stats",
    tags=["Dashboard"],
    summary="Dashboard statistics",
    description="Returns aggregate counts: total events, detections (overall and last 24 h), "
                "total devices, breakdowns by event type, model, and severity.",
    response_model=StatsResponse,
)
async def api_stats(session: AsyncSession = Depends(get_session)):
    """Get dashboard stats as JSON."""
    return await get_stats(session)


@router.get(
    "/api/v1/recent-detections",
    tags=["Incidents"],
    summary="Recent detections",
    description="Returns the most recent detections ordered by last activity. "
                "Useful for live-feed widgets.",
    response_model=List[DetectionItem],
)
async def api_recent_detections(
    limit: int = Query(10, ge=1, le=50, description="Max items to return"),
    session: AsyncSession = Depends(get_session)
):
    """Get recent detections as JSON."""
    return await get_recent_detections(session, limit=limit)


@router.get(
    "/api/v1/devices",
    tags=["Devices"],
    summary="List all devices",
    description="Returns every registered sensor/device with online status, approval status, "
                "and alert counts for the last 1 h and 24 h.",
    response_model=List[DeviceSummaryItem],
)
async def api_devices(session: AsyncSession = Depends(get_session)):
    """Get devices summary as JSON."""
    return await get_devices_summary(session)


@router.get(
    "/api/v1/devices/{device_id}",
    tags=["Devices"],
    summary="Device detail",
    description="Returns profile, recent alerts (limit 50), and per-label alert statistics "
                "for a single device.",
    response_model=DeviceDetailResponse,
    responses={404: {"model": ErrorResponse, "description": "Device not found"}},
)
async def api_device_detail(
    device_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Get device detail as JSON."""
    data = await get_device_detail(session, device_id)
    if not data:
        return {"error": "Device not found"}
    return data


@router.get(
    "/api/v1/dashboard/analytics",
    tags=["Dashboard"],
    summary="Dashboard analytics",
    description="Returns chart-ready data for: detection timeline (hourly), severity breakdown, "
                "top 8 attack types, top 8 source IPs, top 8 devices, and aggregate summary.",
    response_model=DashboardAnalyticsResponse,
)
async def api_dashboard_analytics(
    window: str = Query("24h", description="Time window: 24h, 12h, 6h, 1h"),
    session: AsyncSession = Depends(get_session)
):
    """
    Get dashboard analytics data for charts.
    
    Returns JSON with:
    - timeseries: Detection counts per hour
    - severity: Count by severity level
    - top_labels: Top 8 attack types
    - top_attackers: Top 8 source IPs
    - by_device: Top 8 devices by alert count
    - summary: Aggregate stats
    """
    # Parse window
    window_hours = 24
    if window == "12h":
        window_hours = 12
    elif window == "6h":
        window_hours = 6
    elif window == "1h":
        window_hours = 1
    
    analytics = await get_dashboard_analytics(session, window_hours=window_hours)
    analytics["window"] = window
    
    return analytics


@router.get(
    "/api/v1/health/models",
    tags=["Health"],
    summary="ML models health",
    description="Returns load status and configuration for every ML model "
                "(SSH LSTM, Network ML).  Network ML is currently REMOVED.",
    response_model=ModelsHealthResponse,
)
async def api_health_models():
    """
    Get ML models health status and detector counters.
    
    Returns:
        - models: Status of all loaded models (ssh_lstm, network_ml)
        - network_ml_detector: Health info including counters and filter flags
    """
    return {
        "models": get_models_status(),
        "network_ml_detector": {"status": "REMOVED"},
    }


# =====================================================
# REPORTS PAGE
# =====================================================

@router.get("/reports", response_class=HTMLResponse, include_in_schema=False)
async def reports_page(
    request: Request,
    report_type: Optional[str] = Query("auth"),
    severity: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    last_minutes: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session)
):
    """Reports page with filtering and export options."""
    # Convert last_minutes to int, handling empty string
    last_minutes_int = int(last_minutes) if last_minutes and last_minutes.strip() else None
    severity_clean = severity if severity and severity.strip() else None
    device_id_clean = device_id if device_id and device_id.strip() else None
    
    # Map report_type to model_name filter
    model_name = None
    if report_type == "auth":
        model_name = "ssh_lstm"
    elif report_type == "network":
        model_name = "suricata"
    # "device" type uses no model filter, just device_id
    
    # Get filtered detections for preview (limit 200)
    detections = await get_detections_filtered(
        session,
        severity=severity_clean,
        model_name=model_name,
        device_id=device_id_clean,
        last_minutes=last_minutes_int,
        limit=200  # Safe preview limit
    )
    
    # Get device list for filter dropdown
    device_ids = await get_all_device_ids(session)
    
    # Build filters dict
    filters_dict = {
        "report_type": report_type,
        "severity": severity_clean,
        "device_id": device_id_clean,
        "last_minutes": last_minutes_int
    }
    
    # Pre-serialize to JSON for template embedding (avoids Jinja2 tojson issues)
    # Note: get_detections_filtered already returns dicts, so use dict key access
    detections_list = []
    for d in detections:
        detections_list.append({
            "id": d.get("id"),
            "ts": str(d.get("ts", "")) if d.get("ts") else None,
            "severity": d.get("severity"),
            "model_name": d.get("model_name"),
            "label": d.get("label"),
            "device_id": d.get("device_id"),
            "score": float(d.get("score", 0) or 0),
            "occurrences": d.get("occurrences", 1),
            "details": d.get("details", {})
        })
    
    detections_json = json.dumps(detections_list, default=str)
    filters_json = json.dumps(filters_dict, default=str)
    
    return templates.TemplateResponse("reports.html", {
        "request": request,
        "detections": detections,
        "detections_json": detections_json,
        "filters_json": filters_json,
        "device_ids": device_ids,
        "filters": filters_dict,
        "page_title": "Reports",
        "now": datetime.utcnow().isoformat()
    })


# =====================================================
# REPORTS EXPORT API
# =====================================================

@router.get(
    "/api/v1/reports/export",
    tags=["Reports"],
    summary="Export detections report",
    description="Download detections as a CSV or XLSX file. Maximum 5 000 rows per export. "
                "Use query params to filter by type, severity, device, and time range.",
    responses={
        200: {"description": "File download (CSV or XLSX)"},
        422: {"model": ReportExportError, "description": "Invalid report type or format"},
    },
)
async def export_report(
    type: str = Query(..., description="Report type: auth, network, or device"),
    format: str = Query("csv", description="Export format: csv or xlsx"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    device_id: Optional[str] = Query(None, description="Filter by device ID"),
    last_minutes: Optional[str] = Query(None, description="Only include last N minutes"),
    session: AsyncSession = Depends(get_session)
):
    """
    Export detections as CSV or XLSX.
    
    Safety limits:
    - Maximum 5000 rows per export
    - Validates type and format parameters
    """
    # Clean parameters (handle empty strings)
    severity_clean = severity if severity and severity.strip() else None
    device_id_clean = device_id if device_id and device_id.strip() else None
    last_minutes_int = int(last_minutes) if last_minutes and last_minutes.strip() else None
    
    # Validate type
    if type not in ("auth", "network", "device"):
        return {"error": "Invalid report type. Use: auth, network, or device"}
    
    # Validate format
    if format not in ("csv", "xlsx"):
        return {"error": "Invalid format. Use: csv or xlsx"}
    
    # Map type to model_name
    model_name = None
    if type == "auth":
        model_name = "ssh_lstm"
    elif type == "network":
        model_name = "suricata"
    
    # Get filtered detections (max 5000)
    detections = await get_detections_filtered(
        session,
        severity=severity_clean,
        model_name=model_name,
        device_id=device_id_clean,
        last_minutes=last_minutes_int,
        limit=5000  # Safety limit for exports
    )
    
    # Prepare data rows
    headers = ["ID", "Timestamp", "Severity", "Model", "Label", "Device", "Score", "Occurrences"]
    rows = []
    for d in detections:
        rows.append([
            d.get("id", ""),
            d.get("ts", "")[:19] if d.get("ts") else "",
            d.get("severity", ""),
            d.get("model_name", ""),
            d.get("label", ""),
            d.get("device_id", ""),
            d.get("score", 0),
            d.get("occurrences", 1)
        ])
    
    # Generate filename
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{type}_{timestamp}"
    
    if format == "csv":
        # Generate CSV
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}.csv"
            }
        )
    
    elif format == "xlsx":
        # Generate XLSX using openpyxl via pandas
        try:
            import pandas as pd
            
            df = pd.DataFrame(rows, columns=headers)
            output = BytesIO()
            
            with pd.ExcelWriter(output, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name="Detections", index=False)
            
            output.seek(0)
            
            return StreamingResponse(
                output,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}.xlsx"
                }
            )
        except ImportError:
            return {"error": "XLSX export requires pandas and openpyxl. Please install: pip install pandas openpyxl"}

