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


def get_network_ml_severity(label: str, score: float) -> str:
    """
    Determine severity for network ML (RF) detections.
    
    Args:
        label: Predicted attack label from RF model
        score: Confidence score (0-1)
    
    Returns:
        Severity string
    
    RF Model Labels:
        - Normal Traffic (benign - should not reach here)
        - Port Scanning
        - Brute Force
        - DoS
        - DDoS
        - Bots
        - Web Attacks
    """
    label_lower = label.lower() if label else ""
    
    # CRITICAL: DDoS attacks - distributed denial of service
    if "ddos" in label_lower:
        return CRITICAL
    
    # HIGH/CRITICAL: DoS attacks based on confidence
    if "dos" in label_lower:
        if score >= 0.90:
            return CRITICAL
        return HIGH
    
    # HIGH: Brute force attacks
    if "brute" in label_lower:
        return HIGH
    
    # HIGH: Web attacks (SQL injection, XSS, etc.)
    if "web" in label_lower:
        return HIGH
    
    # MEDIUM: Port scanning
    if "scan" in label_lower or "portscan" in label_lower:
        return MEDIUM
    
    # MEDIUM: Bot traffic
    if "bot" in label_lower:
        return MEDIUM
    
    # Default based on score
    if score >= 0.95:
        return HIGH
    elif score >= 0.80:
        return MEDIUM
    else:
        return LOW


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
