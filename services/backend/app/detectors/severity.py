"""
Analytical-Intelligence v1 - Severity Classification
"""

from typing import Optional, Tuple


# Severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"





def get_ssh_severity(failed_count: int, is_model_anomaly: bool, score: float = 0.0) -> str:
    """
    Determine severity for SSH LSTM detections.
    
    Args:
        failed_count: Number of failed attempts in time window
        is_model_anomaly: Whether the model flagged anomaly
        score: Model anomaly score
    
    Returns:
        Severity string
    """
    # Very high failed count = CRITICAL
    if failed_count >= 20:
        return CRITICAL
    
    # High failed count or strong model signal = HIGH
    if failed_count >= 10 or (is_model_anomaly and score >= 0.9):
        return HIGH
    
    # Moderate failed count or model anomaly
    if failed_count >= 5 or is_model_anomaly:
        return MEDIUM
    
    # Low
    return LOW
