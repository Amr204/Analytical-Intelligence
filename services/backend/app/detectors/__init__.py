"""
Analytical-Intelligence v1 - Detectors Package
"""

from app.detectors.severity import (
    get_ssh_severity,
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
)
from app.detectors.ssh_lstm_detector import analyze_auth_event

__all__ = [
    "get_ssh_severity",
    "analyze_auth_event",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]
