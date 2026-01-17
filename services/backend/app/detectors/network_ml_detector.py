"""
Analytical-Intelligence v1 - Network ML Detector
Classifies network flows using the trained Random Forest model.

Label Allowlist:
Only these attack types create detection records (configurable via ENV):
- DoS
- DDoS
- Port Scanning
- Brute Force

Other labels (Bots, Web Attacks) are filtered based on NETWORK_NON_ALLOW_ACTION.
"""

import logging
from typing import Dict, Any, Optional, Tuple

import numpy as np

from app.models_loader import network_ml_model
from app.detectors.network_feature_mapper import map_flow_to_features, preprocess_features
from app.detectors.severity import get_network_ml_severity
from app.config import settings

logger = logging.getLogger(__name__)
logger.debug(f"NETWORK_ML_THRESHOLD={settings.network_ml_threshold}")
logger.debug(f"NETWORK_LABEL_ALLOWLIST={settings.network_label_allowlist}")
logger.debug(f"NETWORK_NON_ALLOW_ACTION={settings.network_non_allow_action}")


def is_label_allowed(label: str) -> bool:
    """
    Check if a label is in the allowlist.
    
    Args:
        label: Predicted attack label
    
    Returns:
        True if label is allowed, False otherwise
    """
    allowlist = settings.network_label_allowlist_set
    if not allowlist:
        # Empty allowlist = allow all (backwards compatibility)
        return True
    return label in allowlist


def analyze_flow(flow_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Analyze a network flow using the RF model.
    
    Args:
        flow_data: Flow statistics from NFStream
    
    Returns:
        Detection dict if attack detected AND in allowlist, None otherwise
    """
    if not network_ml_model.loaded:
        logger.debug("Network RF model not loaded, skipping flow analysis")
        return None
    
    # Early filtering for Broadcast/DHCP to reduce false positives
    src_ip = flow_data.get("src_ip", "")
    dst_ip = flow_data.get("dst_ip", "")
    dst_port = flow_data.get("dst_port", 0)

    if (
        src_ip == "0.0.0.0" or 
        dst_ip == "255.255.255.255" or 
        dst_port in [67, 68] or 
        str(dst_ip).lower().startswith("ff02:") or 
        src_ip == "::"
    ):
        logger.debug(f"Skipped broadcast/DHCP flow: {src_ip} -> {dst_ip}:{dst_port}")
        return None
    
    try:
        # Map flow to feature vector
        features, debug_info = map_flow_to_features(flow_data)
        
        if len(features) == 0:
            return None
        
        # Preprocess
        features = preprocess_features(features)
        
        # Predict
        label, score, proba = network_ml_model.predict(features)

        # Normalize label for comparison
        label_norm = (label or "").strip()

        # Reject benign/unknown/empty - RF uses "Normal Traffic" as benign
        benign_label = network_ml_model.benign_label
        if label_norm == benign_label or label_norm.upper() in ("UNKNOWN", "BENIGN", ""):
            return None

        # Reject labels not in known label map (when model loaded)
        known = set(network_ml_model.label_map.keys()) if network_ml_model.loaded else set()
        if known and label not in known:
            logger.debug(f"Unknown label rejected: {label}")
            return None

        # ============================================================
        # ALLOWLIST FILTERING
        # Only create detection for allowed labels (DoS, DDoS, Port Scanning, Brute Force)
        # ============================================================
        if not is_label_allowed(label):
            action = settings.network_non_allow_action.lower()
            if action == "ignore":
                logger.debug(f"Label '{label}' not in allowlist, ignoring (no detection)")
                return None
            elif action == "map_to_normal":
                # Log but don't create detection
                logger.info(f"Label '{label}' not in allowlist, mapped to normal (no detection)")
                return None
            else:
                # Default: ignore
                logger.debug(f"Label '{label}' not in allowlist, ignoring")
                return None

        # Gating Layer: Rule-based Sanity Checks
        # Validate that the traffic volume supports the attack claim
        duration_ms = flow_data.get("bidirectional_duration_ms", 0)
        total_packets = flow_data.get("bidirectional_packets", 0)
        total_bytes = flow_data.get("bidirectional_bytes", 0)
        
        # Avoid division by zero
        duration_sec = max(duration_ms / 1000.0, 0.001)
        
        pps = total_packets / duration_sec
        bps = total_bytes / duration_sec
        
        # Check against thresholds for volume-based attack labels
        # DoS/DDoS/Brute Force typically require significant traffic volume
        volume_attacks = ["DDOS", "DOS", "BRUTE"]
        is_volume_attack = any(v in label_norm.upper() for v in volume_attacks)
        
        if is_volume_attack:
            if pps < settings.ml_min_flow_rate_pps:
                logger.debug(f"Gating filtered {label}: PPS {pps:.2f} < {settings.ml_min_flow_rate_pps}")
                return None
            if bps < settings.ml_min_bytes_per_second:
                logger.debug(f"Gating filtered {label}: BPS {bps:.2f} < {settings.ml_min_bytes_per_second}")
                return None

        logger.debug(f"Flow prediction: {label} (score={score:.3f}, pps={pps:.1f})")

        # Only create detection for non-benign with sufficient confidence
        if score >= settings.network_ml_threshold:
            severity = get_network_ml_severity(label, score)
            
            # Build detection details
            details = {
                "label": label,
                "confidence": round(score, 4),
                "src_ip": flow_data.get("src_ip"),
                "dst_ip": flow_data.get("dst_ip"),
                "src_port": flow_data.get("src_port"),
                "dst_port": flow_data.get("dst_port"),
                "protocol": flow_data.get("protocol"),
                "duration_ms": flow_data.get("bidirectional_duration_ms"),
                "total_bytes": flow_data.get("bidirectional_bytes"),
                "total_packets": flow_data.get("bidirectional_packets"),
                "probabilities": {
                    network_ml_model.inverse_label_map.get(i, str(i)): round(float(p), 4)
                    for i, p in enumerate(proba)
                } if len(proba) > 0 else {}
            }
            
            return {
                "model_name": "network_rf",
                "label": label,
                "score": score,
                "severity": severity,
                "details": details
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Flow analysis error: {e}")
        return None


def get_allowed_labels() -> list:
    """Get list of allowed attack labels for UI display."""
    return list(settings.network_label_allowlist_set)


def get_model_info() -> Dict[str, Any]:
    """Get network RF model information."""
    return {
        "loaded": network_ml_model.loaded,
        "features_count": len(network_ml_model.feature_list),
        "labels": list(network_ml_model.label_map.keys()),
        "allowed_labels": get_allowed_labels(),
        "threshold": settings.network_ml_threshold,
        "benign_label": network_ml_model.benign_label,
    }
