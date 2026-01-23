"""
Analytical-Intelligence v1 - Network Feature Mapper
Maps NFStream flow data to CIC-IDS2017 feature format for Random Forest model.

The RF model expects 52 features with specific names containing spaces.
NFStream provides different field names, so this module handles the mapping.

UNIT CONVENTION:
- NFStream provides IAT values in MILLISECONDS (ms)
- CIC-IDS2017 training data uses MICROSECONDS (µs)
- All IAT-related features are converted: ms * 1000 = µs
"""

import os
import numpy as np
from typing import Dict, Any, List, Tuple
import logging

from app.models_loader import network_ml_model

logger = logging.getLogger(__name__)

# Environment-configurable minimum duration for rate calculations
# If duration_ms < this value, rate features are set to 0 to avoid inflation
MIN_FLOW_DURATION_MS = int(os.environ.get("MIN_FLOW_DURATION_MS", "50"))


def normalize_feature_name(name: str) -> str:
    """
    Normalize CIC-IDS feature name by removing spaces.
    Example: "Destination Port" -> "DestinationPort"
    """
    return name.replace(" ", "")


# Mapping from normalized CIC-IDS feature names to NFStream field names
# None means the feature needs special computation or will be filled with 0.0
FEATURE_MAPPING = {
    # Direct mappings
    "DestinationPort": "dst_port",
    "FlowDuration": "bidirectional_duration_ms",  # Will convert ms to microseconds
    
    # Forward packet counts and bytes
    "TotalFwdPackets": "src2dst_packets",
    "TotalLengthofFwdPackets": "src2dst_bytes",
    
    # Forward packet length stats
    "FwdPacketLengthMax": "src2dst_max_ps",
    "FwdPacketLengthMin": "src2dst_min_ps",
    "FwdPacketLengthMean": "src2dst_mean_ps",
    "FwdPacketLengthStd": "src2dst_stddev_ps",
    
    # Backward packet length stats
    "BwdPacketLengthMax": "dst2src_max_ps",
    "BwdPacketLengthMin": "dst2src_min_ps",
    "BwdPacketLengthMean": "dst2src_mean_ps",
    "BwdPacketLengthStd": "dst2src_stddev_ps",
    
    # Overall packet stats
    "MinPacketLength": "bidirectional_min_ps",
    "MaxPacketLength": "bidirectional_max_ps",
    "PacketLengthMean": "bidirectional_mean_ps",
    "PacketLengthStd": "bidirectional_stddev_ps",
    
    # TCP flags
    "FINFlagCount": "bidirectional_fin_packets",
    "PSHFlagCount": "bidirectional_psh_packets",
    "ACKFlagCount": "bidirectional_ack_packets",
    
    # Subflow (same as total for single flows)
    "SubflowFwdBytes": "src2dst_bytes",

    # IAT features - NFStream provides these in milliseconds
    # Will be converted to microseconds during mapping
    "FlowIATMean": "bidirectional_mean_piat_ms",
    "FlowIATStd": "bidirectional_stddev_piat_ms",
    "FlowIATMax": "bidirectional_max_piat_ms",
    "FlowIATMin": "bidirectional_min_piat_ms",
    
    # Forward IAT
    "FwdIATTotal": None,  # Computed: sum of IATs
    "FwdIATMean": "src2dst_mean_piat_ms",
    "FwdIATStd": "src2dst_stddev_piat_ms",
    "FwdIATMax": "src2dst_max_piat_ms",
    "FwdIATMin": "src2dst_min_piat_ms",
    
    # Backward IAT
    "BwdIATTotal": None,  # Computed
    "BwdIATMean": "dst2src_mean_piat_ms",
    "BwdIATStd": "dst2src_stddev_piat_ms",
    "BwdIATMax": "dst2src_max_piat_ms",
    "BwdIATMin": "dst2src_min_piat_ms",
    
    # Features that need computation
    "FlowBytes/s": None,  # Computed: bytes / duration_sec
    "FlowPackets/s": None,  # Computed: packets / duration_sec
    "FwdPackets/s": None,  # Computed: fwd_packets / duration_sec
    "BwdPackets/s": None,  # Computed: bwd_packets / duration_sec
    "PacketLengthVariance": None,  # Computed: std^2
    "AveragePacketSize": None,  # Computed: bytes / packets
    
    # Header lengths - not available in NFStream, fill with 0
    "FwdHeaderLength": None,
    "BwdHeaderLength": None,
    
    # Window bytes - not available in NFStream
    "Init_Win_bytes_forward": None,
    "Init_Win_bytes_backward": None,
    
    # Other
    "act_data_pkt_fwd": None,  # Active data packets forward
    "min_seg_size_forward": None,  # Minimum segment size
    
    # Active/Idle metrics - not typically available
    "ActiveMean": None,
    "ActiveMax": None,
    "ActiveMin": None,
    "IdleMean": None,
    "IdleMax": None,
    "IdleMin": None,
}

# IAT features that need ms -> µs conversion (multiply by 1000)
# CIC-IDS2017 training data uses microseconds for all IAT values
IAT_FEATURES_TO_CONVERT_MS_TO_US = {
    "FlowIATMean", "FlowIATStd", "FlowIATMax", "FlowIATMin",
    "FwdIATTotal", "FwdIATMean", "FwdIATStd", "FwdIATMax", "FwdIATMin",
    "BwdIATTotal", "BwdIATMean", "BwdIATStd", "BwdIATMax", "BwdIATMin",
}


def map_flow_to_features(flow_data: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Map NFStream flow data to CIC-IDS feature vector for RF model.
    
    Args:
        flow_data: Dictionary of flow statistics from NFStream
    
    Returns:
        Tuple of (feature_vector, debug_info)
        - feature_vector: numpy array of shape (52,) matching feature_list order
        - debug_info: dict with mapping statistics for logging
    """
    if not network_ml_model.loaded:
        return np.array([]), {}
    
    feature_list = network_ml_model.feature_list
    median_map = network_ml_model.median_map
    
    features = np.zeros(len(feature_list), dtype=np.float64)
    missing_features = []
    mapped_count = 0
    fallback_count = 0
    
    # Pre-compute common values
    duration_ms = flow_data.get("bidirectional_duration_ms", 0) or 0
    duration_us = duration_ms * 1000  # Convert to microseconds for CIC-IDS format
    
    # For rate features: if duration too small, use 0 to prevent artificial inflation
    # This prevents tiny/zero duration flows from generating extreme PPS/BPS values
    # that the RF model interprets as DDoS characteristics
    if duration_ms >= MIN_FLOW_DURATION_MS:
        rate_safe_duration_sec = duration_ms / 1000.0
    else:
        rate_safe_duration_sec = 0.0  # Will result in rate features = 0
    
    total_bytes = flow_data.get("bidirectional_bytes", 0) or 0
    total_packets = flow_data.get("bidirectional_packets", 0) or 0
    fwd_packets = flow_data.get("src2dst_packets", 0) or 0
    bwd_packets = flow_data.get("dst2src_packets", 0) or 0
    fwd_bytes = flow_data.get("src2dst_bytes", 0) or 0
    
    std_ps = flow_data.get("bidirectional_stddev_ps", 0) or 0
    
    for i, feature_name in enumerate(feature_list):
        # Normalize the feature name for lookup
        normalized_name = normalize_feature_name(feature_name)
        nfstream_field = FEATURE_MAPPING.get(normalized_name)
        
        value = None
        was_mapped = False
        
        # Try direct mapping first
        if nfstream_field and nfstream_field in flow_data:
            value = flow_data.get(nfstream_field)
            was_mapped = True
            
            # Special handling for FlowDuration (ms to microseconds)
            if normalized_name == "FlowDuration" and value is not None:
                value = value * 1000  # Convert ms to microseconds
        
        # Compute derived features if no direct mapping
        if value is None:
            if normalized_name == "FlowBytes/s":
                # Use safe duration to prevent inflation
                value = total_bytes / rate_safe_duration_sec if rate_safe_duration_sec > 0 else 0.0
                
            elif normalized_name == "FlowPackets/s":
                value = total_packets / rate_safe_duration_sec if rate_safe_duration_sec > 0 else 0.0
                
            elif normalized_name == "FwdPackets/s":
                value = fwd_packets / rate_safe_duration_sec if rate_safe_duration_sec > 0 else 0.0
                
            elif normalized_name == "BwdPackets/s":
                value = bwd_packets / rate_safe_duration_sec if rate_safe_duration_sec > 0 else 0.0
                
            elif normalized_name == "AveragePacketSize":
                value = total_bytes / total_packets if total_packets > 0 else 0.0
                
            elif normalized_name == "PacketLengthVariance":
                value = std_ps ** 2 if std_ps else 0.0
                
            elif normalized_name == "FwdIATTotal":
                # Approximate: mean IAT * (packets - 1), then convert ms → µs
                mean_iat = flow_data.get("src2dst_mean_piat_ms", 0) or 0
                value = mean_iat * max(fwd_packets - 1, 0) * 1000  # ms → µs
                was_mapped = True  # Derived from real data
                
            elif normalized_name == "BwdIATTotal":
                mean_iat = flow_data.get("dst2src_mean_piat_ms", 0) or 0
                value = mean_iat * max(bwd_packets - 1, 0) * 1000  # ms → µs
                was_mapped = True  # Derived from real data
        
        # Convert IAT features from ms to µs (CIC-IDS2017 uses microseconds)
        if normalized_name in IAT_FEATURES_TO_CONVERT_MS_TO_US and value is not None:
            if normalized_name not in ("FwdIATTotal", "BwdIATTotal"):  # Already converted above
                value = value * 1000  # ms → µs
        
        # Use median from preprocess config if available, otherwise 0.0
        if value is None:
            value = median_map.get(feature_name, 0.0)
            if feature_name not in median_map:
                missing_features.append(feature_name)
            fallback_count += 1
        elif was_mapped:
            mapped_count += 1
        
        # Handle NaN/Inf
        if value is None or not np.isfinite(value):
            value = median_map.get(feature_name, 0.0)
            fallback_count += 1
            mapped_count = max(0, mapped_count - 1)  # Adjust if previously counted
        
        features[i] = float(value)
    
    debug_info = {
        "mapped_count": mapped_count,
        "fallback_count": fallback_count,
        "missing_features_count": len(missing_features),
        "total_features": len(feature_list),
        "duration_ms": duration_ms,
        "rate_safe": rate_safe_duration_sec > 0,
    }
    
    if missing_features and len(missing_features) < 10:
        debug_info["missing_features"] = missing_features
    
    return features, debug_info


def preprocess_features(features: np.ndarray) -> np.ndarray:
    """
    Apply preprocessing: fill NaN with 0, clip extreme values.
    For RF model, preprocessing is minimal - just ensure no NaN/Inf.
    """
    if not network_ml_model.loaded or len(features) == 0:
        return features
    
    feature_list = network_ml_model.feature_list
    median_map = network_ml_model.median_map
    columns_to_clip = network_ml_model.columns_to_clip
    
    # Replace NaN/Inf with 0 or median
    for i, feature_name in enumerate(feature_list):
        if not np.isfinite(features[i]):
            features[i] = median_map.get(feature_name, 0.0)
    
    # Clip extreme values for rate-based columns (prevent unrealistic values)
    # These columns can have very large values that may affect predictions
    for i, feature_name in enumerate(feature_list):
        normalized = normalize_feature_name(feature_name)
        if normalized in columns_to_clip or feature_name in columns_to_clip:
            # Clip to reasonable maximum (1e9 for bytes/s or packets/s)
            features[i] = np.clip(features[i], 0, 1e9)
    
    return features
