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

Debug Mode:
Set NETWORK_ML_DEBUG=1 to log prediction details for sampled flows.
Set NETWORK_ML_DEBUG_SAMPLE_RATE=N to log 1 out of every N flows (default 50).
"""

import os
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

# Debug mode configuration
NETWORK_ML_DEBUG = os.environ.get("NETWORK_ML_DEBUG", "0") == "1"
DEBUG_SAMPLE_RATE = int(os.environ.get("NETWORK_ML_DEBUG_SAMPLE_RATE", "50"))

# Volume attack gating thresholds (configurable via ENV)
# These prevent false positives from tiny flows being classified as DoS/DDoS
MIN_VOLUME_ATTACK_DURATION_MS = int(os.environ.get("MIN_VOLUME_ATTACK_DURATION_MS", "100"))
MIN_VOLUME_ATTACK_PACKETS = int(os.environ.get("MIN_VOLUME_ATTACK_PACKETS", "10"))
MIN_VOLUME_ATTACK_BYTES = int(os.environ.get("MIN_VOLUME_ATTACK_BYTES", "1000"))

# Global flow counter for debug sampling
_flow_counter = 0


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
    global _flow_counter
    _flow_counter += 1
    should_debug = NETWORK_ML_DEBUG and (_flow_counter % DEBUG_SAMPLE_RATE == 0)
    
    if not network_ml_model.loaded:
        logger.debug("Network RF model not loaded, skipping flow analysis")
        return None
    
    # Early filtering for Broadcast/DHCP to reduce false positives
    src_ip = flow_data.get("src_ip", "")
    dst_ip = flow_data.get("dst_ip", "")
    dst_port = flow_data.get("dst_port", 0)
    protocol = flow_data.get("protocol", "")

    if (
        src_ip == "0.0.0.0" or 
        dst_ip == "255.255.255.255" or 
        dst_port in [67, 68] or 
        str(dst_ip).lower().startswith("ff02:") or 
        src_ip == "::"
    ):
        if should_debug:
            logger.info(f"[DEBUG] DROPPED broadcast/DHCP: {src_ip} -> {dst_ip}:{dst_port}")
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
        
        # Extract flow metrics for gating
        duration_ms = flow_data.get("bidirectional_duration_ms", 0) or 0
        total_packets = flow_data.get("bidirectional_packets", 0) or 0
        total_bytes = flow_data.get("bidirectional_bytes", 0) or 0
        
        # Get top-3 predictions for debug logging
        top3_str = ""
        if should_debug and len(proba) > 0:
            top3_idx = np.argsort(proba)[-3:][::-1]
            top3 = [(network_ml_model.inverse_label_map.get(int(network_ml_model.model.classes_[i]) if hasattr(network_ml_model.model, 'classes_') else i, str(i)), 
                     float(proba[i])) for i in top3_idx]
            top3_str = ", ".join([f"{lbl}:{p:.3f}" for lbl, p in top3])

        # Reject benign/unknown/empty - RF uses "Normal Traffic" as benign
        benign_label = network_ml_model.benign_label
        if label_norm == benign_label or label_norm.upper() in ("UNKNOWN", "BENIGN", ""):
            if should_debug:
                logger.info(
                    f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                    f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                    f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                    f"top3=[{top3_str}] -> BENIGN"
                )
            return None

        # Reject labels not in known label map (when model loaded)
        known = set(network_ml_model.label_map.keys()) if network_ml_model.loaded else set()
        if known and label not in known:
            if should_debug:
                logger.info(f"[DEBUG] Unknown label rejected: {label}")
            return None

        # ============================================================
        # ALLOWLIST FILTERING
        # Only create detection for allowed labels (DoS, DDoS, Port Scanning, Brute Force)
        # ============================================================
        if not is_label_allowed(label):
            action = settings.network_non_allow_action.lower()
            if should_debug:
                logger.info(
                    f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                    f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                    f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                    f"top3=[{top3_str}] -> ALLOWLIST_FILTERED ({label})"
                )
            if action == "ignore":
                logger.debug(f"Label '{label}' not in allowlist, ignoring (no detection)")
                return None
            elif action == "map_to_normal":
                logger.info(f"Label '{label}' not in allowlist, mapped to normal (no detection)")
                return None
            else:
                logger.debug(f"Label '{label}' not in allowlist, ignoring")
                return None

        # ============================================================
        # GATING LAYER: Rule-based Sanity Checks
        # Validate that the traffic volume supports the attack claim
        # ============================================================
        
        # Check against thresholds for volume-based attack labels
        # DoS/DDoS/Brute Force typically require significant traffic volume
        volume_attacks = ["DDOS", "DOS", "BRUTE"]
        is_volume_attack = any(v in label_norm.upper() for v in volume_attacks)
        
        if is_volume_attack:
            # Hard threshold: must have minimum ABSOLUTE values
            # This prevents tiny/zero duration flows from triggering false positives
            if duration_ms < MIN_VOLUME_ATTACK_DURATION_MS:
                if should_debug:
                    logger.info(
                        f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                        f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                        f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                        f"top3=[{top3_str}] -> GATING_DURATION ({label}, {duration_ms}ms < {MIN_VOLUME_ATTACK_DURATION_MS}ms)"
                    )
                logger.debug(f"Gating filtered {label}: duration {duration_ms}ms < {MIN_VOLUME_ATTACK_DURATION_MS}ms")
                return None
            
            if total_packets < MIN_VOLUME_ATTACK_PACKETS:
                if should_debug:
                    logger.info(
                        f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                        f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                        f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                        f"top3=[{top3_str}] -> GATING_PACKETS ({label}, {total_packets} < {MIN_VOLUME_ATTACK_PACKETS})"
                    )
                logger.debug(f"Gating filtered {label}: packets {total_packets} < {MIN_VOLUME_ATTACK_PACKETS}")
                return None
            
            if total_bytes < MIN_VOLUME_ATTACK_BYTES:
                if should_debug:
                    logger.info(
                        f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                        f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                        f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                        f"top3=[{top3_str}] -> GATING_BYTES ({label}, {total_bytes} < {MIN_VOLUME_ATTACK_BYTES})"
                    )
                logger.debug(f"Gating filtered {label}: bytes {total_bytes} < {MIN_VOLUME_ATTACK_BYTES}")
                return None
            
            # Also check rate thresholds (PPS and BPS)
            # Use safe duration calculation to avoid inflated rates
            if duration_ms >= 50:  # Only calculate rates for meaningful durations
                duration_sec = duration_ms / 1000.0
                pps = total_packets / duration_sec
                bps = total_bytes / duration_sec
                
                if pps < settings.ml_min_flow_rate_pps:
                    if should_debug:
                        logger.info(
                            f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                            f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                            f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                            f"top3=[{top3_str}] -> GATING_PPS ({label}, {pps:.1f} < {settings.ml_min_flow_rate_pps})"
                        )
                    logger.debug(f"Gating filtered {label}: PPS {pps:.2f} < {settings.ml_min_flow_rate_pps}")
                    return None
                    
                if bps < settings.ml_min_bytes_per_second:
                    if should_debug:
                        logger.info(
                            f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                            f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                            f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                            f"top3=[{top3_str}] -> GATING_BPS ({label}, {bps:.1f} < {settings.ml_min_bytes_per_second})"
                        )
                    logger.debug(f"Gating filtered {label}: BPS {bps:.2f} < {settings.ml_min_bytes_per_second}")
                    return None

        logger.debug(f"Flow prediction: {label} (score={score:.3f})")

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
                    network_ml_model.inverse_label_map.get(
                        int(network_ml_model.model.classes_[i]) if hasattr(network_ml_model.model, 'classes_') else i,
                        str(i)
                    ): round(float(p), 4)
                    for i, p in enumerate(proba)
                } if len(proba) > 0 else {}
            }
            
            if should_debug:
                logger.info(
                    f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                    f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                    f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                    f"top3=[{top3_str}] -> DETECTION ({label}, score={score:.3f}, severity={severity})"
                )
            
            return {
                "model_name": "network_rf",
                "label": label,
                "score": score,
                "severity": severity,
                "details": details
            }
        
        # Below threshold
        if should_debug:
            logger.info(
                f"[DEBUG] src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                f"top3=[{top3_str}] -> THRESHOLD ({label}, {score:.3f} < {settings.network_ml_threshold})"
            )
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

