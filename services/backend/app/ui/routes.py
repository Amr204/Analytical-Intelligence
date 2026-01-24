"""
Analytical-Intelligence v1 - UI Routes
Server-rendered HTML pages using Jinja2 templates.
"""

from datetime import datetime
from typing import Optional
from io import StringIO, BytesIO
import csv

from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import (
    get_session, 
    get_stats, 
    get_recent_detections,
    get_detections_filtered,
    get_raw_events,
    get_devices_summary,
    get_device_detail,
    get_all_device_ids
)
from app.models_loader import get_models_status

router = APIRouter(tags=["ui"])

# Templates directory
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """Dashboard page with stats and recent alerts."""
    stats = await get_stats(session)
    recent_detections = await get_recent_detections(session, limit=10)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "detections": recent_detections,
        "page_title": "Dashboard",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    severity: Optional[str] = Query(None),
    model_name: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    last_minutes: Optional[int] = Query(None),
    session: AsyncSession = Depends(get_session)
):
    """Alerts/detections list page with filters."""
    detections = await get_detections_filtered(
        session,
        severity=severity,
        model_name=model_name,
        label=label,
        device_id=device_id,
        last_minutes=last_minutes,
        limit=100
    )
    
    # Get device list for filter dropdown
    device_ids = await get_all_device_ids(session)
    
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "detections": detections,
        "device_ids": device_ids,
        "filters": {
            "severity": severity,
            "model_name": model_name,
            "label": label,
            "device_id": device_id,
            "last_minutes": last_minutes
        },
        "page_title": "Alerts",
        "now": datetime.utcnow().isoformat()
    })


@router.get("/devices", response_class=HTMLResponse)
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


@router.get("/devices/{device_id}", response_class=HTMLResponse)
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


@router.get("/events/auth", response_class=HTMLResponse)
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


@router.get("/events/flows", response_class=HTMLResponse)
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


@router.get("/models", response_class=HTMLResponse)
async def models_page(request: Request):
    """ML models status page."""
    models_status = get_models_status()
    
    return templates.TemplateResponse("models.html", {
        "request": request,
        "models": models_status,
        "page_title": "Models",
        "now": datetime.utcnow().isoformat()
    })


# JSON API endpoints for polling
@router.get("/api/v1/stats")
async def api_stats(session: AsyncSession = Depends(get_session)):
    """Get dashboard stats as JSON."""
    return await get_stats(session)


@router.get("/api/v1/recent-detections")
async def api_recent_detections(
    limit: int = Query(10, ge=1, le=50),
    session: AsyncSession = Depends(get_session)
):
    """Get recent detections as JSON."""
    return await get_recent_detections(session, limit=limit)


@router.get("/api/v1/devices")
async def api_devices(session: AsyncSession = Depends(get_session)):
    """Get devices summary as JSON."""
    return await get_devices_summary(session)


@router.get("/api/v1/devices/{device_id}")
async def api_device_detail(
    device_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Get device detail as JSON."""
    data = await get_device_detail(session, device_id)
    if not data:
        return {"error": "Device not found"}
    return data

@router.get("/api/v1/health/models")
async def api_health_models():
    """
    Get ML models health status and detector counters.
    
    Returns:
        - models: Status of all loaded models (ssh_lstm, network_ml)
        - network_ml_detector: Health info including counters and filter flags
    """
    from app.detectors.network_ml_detector import get_network_ml_health
    
    return {
        "models": get_models_status(),
        "network_ml_detector": get_network_ml_health(),
    }


# =====================================================
# REPORTS PAGE
# =====================================================

@router.get("/reports", response_class=HTMLResponse)
async def reports_page(
    request: Request,
    report_type: Optional[str] = Query("auth"),
    severity: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    last_minutes: Optional[int] = Query(None),
    session: AsyncSession = Depends(get_session)
):
    """Reports page with filtering and export options."""
    # Map report_type to model_name filter
    model_name = None
    if report_type == "auth":
        model_name = "ssh_lstm"
    elif report_type == "network":
        model_name = "network_rf"
    # "device" type uses no model filter, just device_id
    
    # Get filtered detections for preview (limit 200)
    detections = await get_detections_filtered(
        session,
        severity=severity,
        model_name=model_name,
        device_id=device_id if report_type == "device" else device_id,
        last_minutes=last_minutes,
        limit=200  # Safe preview limit
    )
    
    # Get device list for filter dropdown
    device_ids = await get_all_device_ids(session)
    
    return templates.TemplateResponse("reports.html", {
        "request": request,
        "detections": detections,
        "device_ids": device_ids,
        "filters": {
            "report_type": report_type,
            "severity": severity,
            "device_id": device_id,
            "last_minutes": last_minutes
        },
        "page_title": "Reports",
        "now": datetime.utcnow().isoformat()
    })


# =====================================================
# REPORTS EXPORT API
# =====================================================

@router.get("/api/v1/reports/export")
async def export_report(
    type: str = Query(..., description="Report type: auth, network, or device"),
    format: str = Query("csv", description="Export format: csv or xlsx"),
    severity: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    last_minutes: Optional[int] = Query(None),
    session: AsyncSession = Depends(get_session)
):
    """
    Export detections as CSV or XLSX.
    
    Safety limits:
    - Maximum 5000 rows per export
    - Validates type and format parameters
    """
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
        model_name = "network_rf"
    
    # Get filtered detections (max 5000)
    detections = await get_detections_filtered(
        session,
        severity=severity,
        model_name=model_name,
        device_id=device_id if type == "device" else device_id,
        last_minutes=last_minutes,
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

