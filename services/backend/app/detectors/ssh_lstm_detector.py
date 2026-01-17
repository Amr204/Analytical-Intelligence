"""
Analytical-Intelligence v1 - SSH LSTM Detector
Detects SSH brute force and anomalous authentication patterns.
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from collections import defaultdict

import numpy as np

from app.models_loader import ssh_lstm_model
from app.detectors.severity import get_ssh_severity
from app.config import settings

logger = logging.getLogger(__name__)


# Token definitions for auth.log parsing
TOKEN_PATTERNS = [
    (r"Failed password for invalid user", "INVALID_USER"),
    (r"Failed password for", "FAILED_PASSWORD"),
    (r"Invalid user", "INVALID_USER"),
    (r"Accepted password for", "ACCEPTED_PASSWORD"),
    (r"Accepted publickey for", "ACCEPTED_PUBLICKEY"),
    (r"Disconnected from", "DISCONNECT"),
    (r"Connection closed by", "CONNECTION_CLOSED"),
    (r"POSSIBLE BREAK-IN ATTEMPT", "REVERSE_DNS_FAIL"),
    (r"Reverse mapping checking", "REVERSE_DNS_FAIL"),
    (r"pam_unix.*authentication failure", "PAM_AUTH_FAILURE"),
    (r"authentication failure", "AUTH_FAILURE"), # Generic fallback
    (r"session opened for user", "SESSION_OPENED"),
    (r"session closed for user", "SESSION_CLOSED"),
]

# IP extraction patterns
IP_PATTERNS = [
    r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    r"rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]",
]


class SSHEventTracker:
    """Tracks SSH events per source IP for anomaly detection."""
    
    def __init__(self):
        # Per-IP rolling token sequences
        self.ip_tokens: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        # Per-IP failed attempt counts
        self.ip_failed_counts: Dict[str, List[datetime]] = defaultdict(list)
    
    def add_event(self, src_ip: str, token_id: int, timestamp: datetime):
        """Add an event to the tracker."""
        self.ip_tokens[src_ip].append((timestamp, token_id))
        
        # Keep only recent events (last hour)
        cutoff = timestamp - timedelta(hours=1)
        self.ip_tokens[src_ip] = [
            (ts, tid) for ts, tid in self.ip_tokens[src_ip]
            if ts > cutoff
        ]
    
    def add_failed_attempt(self, src_ip: str, timestamp: datetime):
        """Record a failed authentication attempt."""
        self.ip_failed_counts[src_ip].append(timestamp)
        
        # Keep only recent attempts
        cutoff = timestamp - timedelta(hours=1)
        self.ip_failed_counts[src_ip] = [
            ts for ts in self.ip_failed_counts[src_ip]
            if ts > cutoff
        ]
    
    def get_failed_count_in_window(self, src_ip: str, timestamp: datetime, window_sec: int) -> int:
        """Get count of failed attempts in the time window."""
        cutoff = timestamp - timedelta(seconds=window_sec)
        return len([ts for ts in self.ip_failed_counts.get(src_ip, []) if ts > cutoff])
    
    def get_token_sequence(self, src_ip: str, window_size: int) -> np.ndarray:
        """Get the latest token sequence for an IP."""
        tokens = self.ip_tokens.get(src_ip, [])
        if not tokens:
            return np.array([], dtype=np.int32)
        
        # Extract just the token IDs, sorted by time
        sorted_tokens = sorted(tokens, key=lambda x: x[0])
        token_ids = [tid for _, tid in sorted_tokens[-window_size:]]
        
        return np.array(token_ids, dtype=np.int32)


# Global tracker instance
ssh_tracker = SSHEventTracker()


def parse_auth_line(line: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse an auth.log line to extract token and source IP.
    
    Returns:
        (token_name, src_ip) or (None, None) if not parseable
    """
    # Extract token type
    token_name = "OTHER"
    for pattern, token in TOKEN_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            token_name = token
            break
    
    # Extract source IP
    src_ip = None
    for pattern in IP_PATTERNS:
        match = re.search(pattern, line)
        if match:
            src_ip = match.group(1)
            break
    
    return token_name, src_ip


def analyze_auth_event(line: str, timestamp: datetime = None) -> Optional[Dict[str, Any]]:
    """
    Analyze an auth.log line for SSH anomalies.
    
    Args:
        line: Raw auth.log line
        timestamp: Event timestamp (defaults to now)
    
    Returns:
        Detection dict if anomaly detected, None otherwise
    """
    logger.debug(f"SSH analyze_auth_event called with line: {line[:100]}...")
    
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    # Parse the line
    token_name, src_ip = parse_auth_line(line)
    logger.debug(f"SSH parsed: token={token_name}, src_ip={src_ip}")
    
    if src_ip is None:
        # Can't track without IP
        logger.debug("SSH detection skipped: no source IP found")
        return None
    
    # Get token ID
    if ssh_lstm_model.loaded:
        token_id = ssh_lstm_model.token2id.get(token_name, ssh_lstm_model.token2id.get("OTHER", 0))
    else:
        token_id = 0
    
    # Track the event
    ssh_tracker.add_event(src_ip, token_id, timestamp)
    
    # Track failed attempts
    if token_name in ["FAILED_PASSWORD", "INVALID_USER", "PAM_AUTH_FAILURE", "AUTH_FAILURE"]:
        ssh_tracker.add_failed_attempt(src_ip, timestamp)
    
    # Check for anomalies
    is_anomaly = False
    anomaly_score = 0.0
    failed_count = 0
    
    logger.debug(f"SSH model status: loaded={ssh_lstm_model.loaded}, model_exists={ssh_lstm_model.model is not None}")
    
    # 1. Model-based detection
    if ssh_lstm_model.loaded and ssh_lstm_model.model is not None:
        token_seq = ssh_tracker.get_token_sequence(src_ip, ssh_lstm_model.window_size)
        logger.debug(f"SSH token_seq length={len(token_seq)} for IP {src_ip}")
        if len(token_seq) >= 3:  # Need some history
            anomaly_score, is_model_anomaly = ssh_lstm_model.predict(token_seq)
            logger.debug(f"SSH model prediction: score={anomaly_score:.4f}, is_anomaly={is_model_anomaly}")
            if is_model_anomaly:
                is_anomaly = True
        else:
            is_model_anomaly = False
            logger.debug(f"SSH model skipped: insufficient token history ({len(token_seq)} < 3)")
    else:
        is_model_anomaly = False
        logger.debug("SSH model not loaded, using threshold-only detection")
    
    # 2. Threshold-based detection (failed attempts)
    # Use config setting for window
    window_sec = settings.ssh_bruteforce_window_seconds
    
    failed_count = ssh_tracker.get_failed_count_in_window(
        src_ip, 
        timestamp, 
        window_sec
    )
    
    fail_threshold = settings.ssh_bruteforce_threshold
    logger.debug(f"SSH threshold check: failed_count={failed_count}, threshold={fail_threshold}")
    
    if failed_count >= fail_threshold:
        is_anomaly = True
    
    if not is_anomaly:
        logger.debug(f"SSH detection skipped for {src_ip}: no anomaly detected")
        return None
    
    logger.info(f"SSH detection TRIGGERED for {src_ip}: failed_count={failed_count}, model_score={anomaly_score:.4f}")
    
    # Determine severity
    severity = get_ssh_severity(failed_count, is_model_anomaly, anomaly_score)
    
    # Build detection
    details = {
        "src_ip": src_ip,
        "token": token_name,
        "failed_count": failed_count,
        "fail_threshold": fail_threshold,
        "model_score": round(anomaly_score, 4),
        "model_threshold": ssh_lstm_model.threshold if ssh_lstm_model.loaded else None,
        "model_triggered": is_model_anomaly,
        "raw_line": line[:500],  # Truncate long lines
        "signature_id": None, # Traceability
    }
    
    # Determine label
    if failed_count >= fail_threshold:
        label = "SSH_BRUTE_FORCE"
    elif is_model_anomaly:
        label = "SSH_ANOMALY"
    else:
        label = "SSH_SUSPICIOUS"
    
    return {
        "model_name": "ssh_lstm",
        "label": label,
        "score": max(anomaly_score, failed_count / 20.0),  # Normalize score
        "severity": severity,
        "details": details
    }


def get_model_info() -> Dict[str, Any]:
    """Get SSH LSTM model information."""
    return {
        "loaded": ssh_lstm_model.loaded,
        "tokens": list(ssh_lstm_model.token2id.keys()) if ssh_lstm_model.loaded else [],
        "window_size": ssh_lstm_model.window_size,
        "threshold": ssh_lstm_model.threshold,
        "fail_threshold": settings.ssh_bruteforce_threshold,
        "time_window_sec": settings.ssh_bruteforce_window_seconds,
    }
