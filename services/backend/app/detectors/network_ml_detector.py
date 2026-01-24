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

Filter Control (ENV-based):
Set NETWORK_ML_STRICT_FILTERS=1 to enable all original filters/gating.
Set NETWORK_ML_DISABLE_GATING=1 (default) to skip volume gating.
Set NETWORK_ML_DISABLE_KNOWN_LABEL_CHECK=1 (default) to skip known-label rejection.
Set NETWORK_ML_DISABLE_BROADCAST_FILTER=1 to skip broadcast/DHCP filtering.
Set NETWORK_ML_DISABLE_ALLOWLIST=1 to skip allowlist filtering.
Set NETWORK_ML_LABEL_NORMALIZATION=1 (default) to normalize label variants.

Per-label Thresholds:
Set NETWORK_ML_LABEL_THRESHOLDS_JSON='{"DoS":0.55,"DDoS":0.60}' for per-label thresholds.
"""

import os
import json
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

# =============================================================================
# Filter Control Flags (default: permissive for detection)
# =============================================================================
NETWORK_ML_STRICT_FILTERS = os.environ.get("NETWORK_ML_STRICT_FILTERS", "0") == "1"
NETWORK_ML_DISABLE_GATING = os.environ.get("NETWORK_ML_DISABLE_GATING", "1") == "1"
NETWORK_ML_DISABLE_ALLOWLIST = os.environ.get("NETWORK_ML_DISABLE_ALLOWLIST", "0") == "1"
NETWORK_ML_DISABLE_BROADCAST_FILTER = os.environ.get("NETWORK_ML_DISABLE_BROADCAST_FILTER", "0") == "1"
NETWORK_ML_DISABLE_KNOWN_LABEL_CHECK = os.environ.get("NETWORK_ML_DISABLE_KNOWN_LABEL_CHECK", "1") == "1"
NETWORK_ML_LABEL_NORMALIZATION = os.environ.get("NETWORK_ML_LABEL_NORMALIZATION", "1") == "1"

# Per-label thresholds (JSON)
NETWORK_ML_LABEL_THRESHOLDS_JSON = os.environ.get("NETWORK_ML_LABEL_THRESHOLDS_JSON", "")
_label_thresholds: Dict[str, float] = {}
try:
    if NETWORK_ML_LABEL_THRESHOLDS_JSON:
        _label_thresholds = json.loads(NETWORK_ML_LABEL_THRESHOLDS_JSON)
        logger.info(f"Per-label thresholds loaded: {_label_thresholds}")
except Exception as e:
    logger.warning(f"Failed to parse NETWORK_ML_LABEL_THRESHOLDS_JSON: {e}")
    _label_thresholds = {}

# =============================================================================
# Module-level counters for observability
# =============================================================================
_counters = {
    "total_flows_seen": 0,
    "flows_skipped_broadcast": 0,
    "flows_skipped_benign": 0,
    "flows_skipped_allowlist": 0,
    "flows_skipped_threshold": 0,
    "flows_skipped_gating": 0,
    "flows_skipped_known_label": 0,
    "flows_exceptions": 0,
    "detections_created": 0,
}

# Global flow counter for debug sampling
_flow_counter = 0

# =============================================================================
# Label Normalization
# =============================================================================
_LABEL_NORMALIZATION_MAP = {
    "portscan": "Port Scanning",
    "portscans": "Port Scanning",
    "port scans": "Port Scanning",
    "bruteforce": "Brute Force",
    "brute-force": "Brute Force",
    "ddos": "DDoS",
    "dos": "DoS",
}


def normalize_label(label: str) -> str:
    """
    Normalize attack label variants to canonical form.
    
    Maps common variants:
    - PortScan -> Port Scanning
    - BruteForce -> Brute Force
    - DDOS -> DDoS
    - DOS -> DoS
    """
    if not NETWORK_ML_LABEL_NORMALIZATION:
        return label.strip() if label else ""
    
    if not label:
        return ""
    
    stripped = label.strip()
    # Create normalized key (lowercase, no spaces/dashes)
    key = stripped.lower().replace(" ", "").replace("-", "")
    
    # Check common mappings
    for pattern, canonical in _LABEL_NORMALIZATION_MAP.items():
        pattern_key = pattern.replace(" ", "").replace("-", "")
        if pattern_key == key:
            return canonical
    
    return stripped


def _safe_class_to_label(class_idx: int) -> str:
    """
    Safely convert class index to label string.
    
    Handles both:
    - String classes (e.g., "DoS", "DDoS") - returns directly
    - Numeric indices (e.g., 0, 1, 2) - maps via inverse_label_map
    
    Never throws - returns str(class_idx) on failure.
    """
    try:
        if not network_ml_model.loaded or network_ml_model.model is None:
            return str(class_idx)
        
        classes = getattr(network_ml_model.model, "classes_", None)
        if classes is None:
            # No classes_ attribute, use inverse_label_map with index as key
            return network_ml_model.inverse_label_map.get(class_idx, str(class_idx))
        
        if class_idx < 0 or class_idx >= len(classes):
            return str(class_idx)
        
        class_key = classes[class_idx]
        # Use the model's _label_from_key method for robust mapping
        return network_ml_model._label_from_key(class_key)
    except Exception:
        return str(class_idx)


def is_label_allowed(label: str) -> bool:
    """
    Check if a label is in the allowlist.
    
    Args:
        label: Predicted attack label (should be normalized first)
    
    Returns:
        True if label is allowed, False otherwise
    """
    if NETWORK_ML_DISABLE_ALLOWLIST:
        return True
    
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
    _counters["total_flows_seen"] += 1
    
    should_debug = NETWORK_ML_DEBUG and (_flow_counter % DEBUG_SAMPLE_RATE == 0)
    
    if not network_ml_model.loaded:
        logger.debug("Network RF model not loaded, skipping flow analysis")
        return None
    
    # Early filtering for Broadcast/DHCP to reduce false positives
    src_ip = flow_data.get("src_ip", "")
    dst_ip = flow_data.get("dst_ip", "")
    dst_port = flow_data.get("dst_port", 0)
    protocol = flow_data.get("protocol", "")

    # Broadcast filter (can be disabled)
    if not NETWORK_ML_DISABLE_BROADCAST_FILTER:
        if (
            src_ip == "0.0.0.0" or 
            dst_ip == "255.255.255.255" or 
            dst_port in [67, 68] or 
            str(dst_ip).lower().startswith("ff02:") or 
            src_ip == "::"
        ):
            _counters["flows_skipped_broadcast"] += 1
            if should_debug:
                logger.info(f"[DEBUG] reason=BROADCAST src={src_ip} dst={dst_ip}:{dst_port}")
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

        # Normalize label immediately after prediction
        label = normalize_label(label)
        
        # Extract flow metrics for gating
        duration_ms = flow_data.get("bidirectional_duration_ms", 0) or 0
        total_packets = flow_data.get("bidirectional_packets", 0) or 0
        total_bytes = flow_data.get("bidirectional_bytes", 0) or 0
        
        # Get top-3 predictions for debug logging (safe version)
        top3_str = ""
        if should_debug and len(proba) > 0:
            try:
                top3_idx = np.argsort(proba)[-3:][::-1]
                top3 = [(_safe_class_to_label(i), float(proba[i])) for i in top3_idx]
                top3_str = ", ".join([f"{lbl}:{p:.3f}" for lbl, p in top3])
            except Exception as e:
                top3_str = f"(error: {e})"

        # Reject benign/unknown/empty - RF uses "Normal Traffic" as benign
        benign_label = network_ml_model.benign_label
        if label == benign_label or label.upper() in ("UNKNOWN", "BENIGN", ""):
            _counters["flows_skipped_benign"] += 1
            if should_debug:
                logger.info(
                    f"[DEBUG] reason=BENIGN label={label} score={score:.3f} "
                    f"src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                    f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                    f"mapped={debug_info.get('mapped_count', '?')} fallback={debug_info.get('fallback_count', '?')} "
                    f"top3=[{top3_str}]"
                )
            return None

        # Known-label check (can be disabled - disabled by default)
        if not NETWORK_ML_DISABLE_KNOWN_LABEL_CHECK:
            known = set(network_ml_model.label_map.keys()) if network_ml_model.loaded else set()
            if known and label not in known:
                _counters["flows_skipped_known_label"] += 1
                if should_debug:
                    logger.info(f"[DEBUG] reason=UNKNOWN_LABEL label={label}")
                return None

        # ============================================================
        # ALLOWLIST FILTERING
        # Only create detection for allowed labels (DoS, DDoS, Port Scanning, Brute Force)
        # ============================================================
        if not is_label_allowed(label):
            _counters["flows_skipped_allowlist"] += 1
            action = settings.network_non_allow_action.lower()
            if should_debug:
                logger.info(
                    f"[DEBUG] reason=ALLOWLIST label={label} score={score:.3f} "
                    f"src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                    f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                    f"top3=[{top3_str}]"
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
        # (Can be disabled via NETWORK_ML_DISABLE_GATING)
        # ============================================================
        
        if not NETWORK_ML_DISABLE_GATING and NETWORK_ML_STRICT_FILTERS:
            # Check against thresholds for volume-based attack labels
            # DoS/DDoS/Brute Force typically require significant traffic volume
            volume_attacks = ["DDOS", "DOS", "BRUTE"]
            is_volume_attack = any(v in label.upper() for v in volume_attacks)
            
            if is_volume_attack:
                # Hard threshold: must have minimum ABSOLUTE values
                # This prevents tiny/zero duration flows from triggering false positives
                if duration_ms < MIN_VOLUME_ATTACK_DURATION_MS:
                    _counters["flows_skipped_gating"] += 1
                    if should_debug:
                        logger.info(
                            f"[DEBUG] reason=GATING_DURATION label={label} score={score:.3f} "
                            f"dur={duration_ms}ms < {MIN_VOLUME_ATTACK_DURATION_MS}ms "
                            f"src={src_ip} dst={dst_ip}:{dst_port}"
                        )
                    logger.debug(f"Gating filtered {label}: duration {duration_ms}ms < {MIN_VOLUME_ATTACK_DURATION_MS}ms")
                    return None
                
                if total_packets < MIN_VOLUME_ATTACK_PACKETS:
                    _counters["flows_skipped_gating"] += 1
                    if should_debug:
                        logger.info(
                            f"[DEBUG] reason=GATING_PACKETS label={label} score={score:.3f} "
                            f"pkts={total_packets} < {MIN_VOLUME_ATTACK_PACKETS} "
                            f"src={src_ip} dst={dst_ip}:{dst_port}"
                        )
                    logger.debug(f"Gating filtered {label}: packets {total_packets} < {MIN_VOLUME_ATTACK_PACKETS}")
                    return None
                
                if total_bytes < MIN_VOLUME_ATTACK_BYTES:
                    _counters["flows_skipped_gating"] += 1
                    if should_debug:
                        logger.info(
                            f"[DEBUG] reason=GATING_BYTES label={label} score={score:.3f} "
                            f"bytes={total_bytes} < {MIN_VOLUME_ATTACK_BYTES} "
                            f"src={src_ip} dst={dst_ip}:{dst_port}"
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
                        _counters["flows_skipped_gating"] += 1
                        if should_debug:
                            logger.info(
                                f"[DEBUG] reason=GATING_PPS label={label} score={score:.3f} "
                                f"pps={pps:.1f} < {settings.ml_min_flow_rate_pps} "
                                f"src={src_ip} dst={dst_ip}:{dst_port}"
                            )
                        logger.debug(f"Gating filtered {label}: PPS {pps:.2f} < {settings.ml_min_flow_rate_pps}")
                        return None
                        
                    if bps < settings.ml_min_bytes_per_second:
                        _counters["flows_skipped_gating"] += 1
                        if should_debug:
                            logger.info(
                                f"[DEBUG] reason=GATING_BPS label={label} score={score:.3f} "
                                f"bps={bps:.1f} < {settings.ml_min_bytes_per_second} "
                                f"src={src_ip} dst={dst_ip}:{dst_port}"
                            )
                        logger.debug(f"Gating filtered {label}: BPS {bps:.2f} < {settings.ml_min_bytes_per_second}")
                        return None

        logger.debug(f"Flow prediction: {label} (score={score:.3f})")

        # ============================================================
        # THRESHOLD CHECK with per-label support
        # ============================================================
        required_threshold = _label_thresholds.get(label, settings.network_ml_threshold)
        
        if score >= required_threshold:
            severity = get_network_ml_severity(label, score)
            
            # Build detection details with class-to-label mapping (safe version)
            probabilities = {}
            if len(proba) > 0:
                try:
                    for i, p in enumerate(proba):
                        lbl = _safe_class_to_label(i)
                        probabilities[lbl] = round(float(p), 4)
                except Exception:
                    probabilities = {}
            
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
                "probabilities": probabilities,
            }
            
            _counters["detections_created"] += 1
            
            if should_debug:
                logger.info(
                    f"[DEBUG] reason=DETECTION label={label} score={score:.3f} threshold={required_threshold} "
                    f"severity={severity} src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                    f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                    f"top3=[{top3_str}]"
                )
            
            return {
                "model_name": "network_rf",
                "label": label,
                "score": score,
                "severity": severity,
                "details": details
            }
        
        # Below threshold
        _counters["flows_skipped_threshold"] += 1
        if should_debug:
            logger.info(
                f"[DEBUG] reason=THRESHOLD label={label} score={score:.3f} threshold={required_threshold} "
                f"src={src_ip} dst={dst_ip}:{dst_port} proto={protocol} "
                f"dur={duration_ms}ms pkts={total_packets} bytes={total_bytes} "
                f"top3=[{top3_str}]"
            )
        return None
        
    except Exception as e:
        _counters["flows_exceptions"] += 1
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


def get_network_ml_health() -> Dict[str, Any]:
    """
    Return health/status info for network ML detector.
    Used by /api/v1/health/models endpoint.
    """
    return {
        "loaded": network_ml_model.loaded,
        "features_count": len(network_ml_model.feature_list) if network_ml_model.loaded else 0,
        "labels_count": len(network_ml_model.label_map) if network_ml_model.loaded else 0,
        "benign_label": network_ml_model.benign_label,
        "allowed_labels": get_allowed_labels(),
        "thresholds": {
            "global": settings.network_ml_threshold,
            "per_label": dict(_label_thresholds),
        },
        "filters": {
            "strict_filters": NETWORK_ML_STRICT_FILTERS,
            "disable_gating": NETWORK_ML_DISABLE_GATING,
            "disable_allowlist": NETWORK_ML_DISABLE_ALLOWLIST,
            "disable_broadcast_filter": NETWORK_ML_DISABLE_BROADCAST_FILTER,
            "disable_known_label_check": NETWORK_ML_DISABLE_KNOWN_LABEL_CHECK,
            "label_normalization": NETWORK_ML_LABEL_NORMALIZATION,
        },
        "counters": dict(_counters),
    }
