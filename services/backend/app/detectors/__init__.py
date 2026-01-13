"""
Analytical-Intelligence v1 - Detectors Package
"""

from app.detectors.severity import (
    get_suricata_severity,
    get_network_ml_severity,
    get_ssh_severity,
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
)
from app.detectors.ssh_lstm_detector import analyze_auth_event
from app.detectors.network_ml_detector import analyze_flow
from app.detectors.network_feature_mapper import map_flow_to_features

__all__ = [
    "get_suricata_severity",
    "get_network_ml_severity", 
    "get_ssh_severity",
    "analyze_auth_event",
    "analyze_flow",
    "map_flow_to_features",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]
