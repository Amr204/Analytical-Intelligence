"""
Analytical-Intelligence v1 - Notification Types
"""

from typing import TypedDict, Optional

# Severity order for comparison (higher value = more severe)
SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def severity_meets_threshold(severity: str, min_severity: str) -> bool:
    """Check if severity meets or exceeds the minimum threshold."""
    sev_val = SEVERITY_ORDER.get(severity.upper(), 0)
    min_val = SEVERITY_ORDER.get(min_severity.upper(), 3)  # Default HIGH
    return sev_val >= min_val


class DetectionAlert(TypedDict, total=False):
    """Structured alert data for notifications."""
    detection_id: int
    timestamp: str
    device_id: str
    model_name: str
    label: str  # Attack type (e.g., "DDoS", "Brute Force")
    score: float
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    reason: Optional[str]
