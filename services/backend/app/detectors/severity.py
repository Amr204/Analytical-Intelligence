"""
Analytical-Intelligence v1 - Severity Classification
"""

from typing import Optional


# Severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


def get_suricata_severity(signature: str, category: str = None, suricata_severity: int = None) -> str:
    """
    Determine severity for Suricata alerts.
    
    Args:
        signature: Alert signature text
        category: Alert category
        suricata_severity: Suricata's own severity (1=highest, 4=lowest)
    
    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, or LOW
    """
    sig_lower = signature.lower() if signature else ""
    cat_lower = category.lower() if category else ""
    
    # CRITICAL: DoS, DDoS, flood attacks
    critical_patterns = [
        "ddos", "dos ", "flood", "amplification",
        "denial of service", "resource exhaustion"
    ]
    for pattern in critical_patterns:
        if pattern in sig_lower or pattern in cat_lower:
            return CRITICAL
    
    # HIGH: Scans, brute force, exploitation attempts
    high_patterns = [
        "scan", "brute", "exploit", "attack",
        "shellcode", "trojan", "malware", "backdoor",
        "command injection", "sql injection", "xss",
        "remote code execution", "rce", "buffer overflow"
    ]
    for pattern in high_patterns:
        if pattern in sig_lower or pattern in cat_lower:
            return HIGH
    
    # Use Suricata's own severity as fallback
    if suricata_severity is not None:
        if suricata_severity == 1:
            return HIGH
        elif suricata_severity == 2:
            return MEDIUM
        else:
            return LOW
    
    # Default
    return MEDIUM


def get_network_ml_severity(label: str, score: float) -> str:
    """
    Determine severity for network ML detections.
    
    Args:
        label: Predicted attack label
        score: Confidence score (0-1)
    
    Returns:
        Severity string
    """
    label_lower = label.lower() if label else ""
    
    # CRITICAL: DDoS attacks
    if "ddos" in label_lower:
        return CRITICAL
    
    # HIGH: DoS attacks
    if "dos" in label_lower:
        if score >= 0.90:
            return CRITICAL
        return HIGH
    
    # HIGH: Brute force attacks
    if "patator" in label_lower or "brute" in label_lower:
        return HIGH
    
    # MEDIUM: Port scans
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
