"""
Mini-SIEM v1 - Network Feature Mapper
Maps NFStream flow data to CIC-IDS2017 feature format.
"""

import numpy as np
from typing import Dict, Any, List

from app.models_loader import network_ml_model


# NFStream to CIC-IDS feature mapping
# Keys are CIC-IDS feature names, values are NFStream field names or None (use median)
NFSTREAM_TO_CIC_MAP = {
    # Direct mappings
    "DestinationPort": "dst_port",
    "FlowDuration": "bidirectional_duration_ms",  # Convert ms to us (*1000)
    
    # Packet counts
    "TotalFwdPackets": "src2dst_packets",
    "TotalBackwardPackets": "dst2src_packets",
    
    # Byte counts
    "TotalLengthofFwdPackets": "src2dst_bytes",
    "TotalLengthofBwdPackets": "dst2src_bytes",
    
    # Packet length stats - forward
    "FwdPacketLengthMax": "src2dst_max_ps",
    "FwdPacketLengthMin": "src2dst_min_ps",
    "FwdPacketLengthMean": "src2dst_mean_ps",
    "FwdPacketLengthStd": "src2dst_stddev_ps",
    
    # Packet length stats - backward
    "BwdPacketLengthMax": "dst2src_max_ps",
    "BwdPacketLengthMin": "dst2src_min_ps",
    "BwdPacketLengthMean": "dst2src_mean_ps",
    "BwdPacketLengthStd": "dst2src_stddev_ps",
    
    # Overall packet stats
    "MinPacketLength": "bidirectional_min_ps",
    "MaxPacketLength": "bidirectional_max_ps",
    "PacketLengthMean": "bidirectional_mean_ps",
    "PacketLengthStd": "bidirectional_stddev_ps",
    
    # These need computation or use median
    "FlowBytes/s": None,  # Computed: bytes / duration
    "FlowPackets/s": None,  # Computed: packets / duration
    "FlowIATMean": None,
    "FlowIATStd": None,
    "FlowIATMax": None,
    "FlowIATMin": None,
    "FwdIATTotal": None,
    "FwdIATMean": None,
    "FwdIATStd": None,
    "FwdIATMax": None,
    "FwdIATMin": None,
    "BwdIATTotal": None,
    "BwdIATMean": None,
    "BwdIATStd": None,
    "BwdIATMax": None,
    "BwdIATMin": None,
    "FwdPSHFlags": None,
    "FwdURGFlags": None,
    "FwdHeaderLength": None,
    "BwdHeaderLength": None,
    "FwdPackets/s": None,
    "BwdPackets/s": None,
    "PacketLengthVariance": None,
    "FINFlagCount": None,
    "SYNFlagCount": None,
    "RSTFlagCount": None,
    "PSHFlagCount": None,
    "ACKFlagCount": None,
    "URGFlagCount": None,
    "CWEFlagCount": None,
    "ECEFlagCount": None,
    "Down/UpRatio": None,
    "AveragePacketSize": None,
    "AvgFwdSegmentSize": None,
    "AvgBwdSegmentSize": None,
    "FwdHeaderLength.1": None,
    "SubflowFwdPackets": "src2dst_packets",
    "SubflowFwdBytes": "src2dst_bytes",
    "SubflowBwdPackets": "dst2src_packets",
    "SubflowBwdBytes": "dst2src_bytes",
    "Init_Win_bytes_forward": None,
    "Init_Win_bytes_backward": None,
    "act_data_pkt_fwd": None,
    "min_seg_size_forward": None,
    "ActiveMean": None,
    "ActiveStd": None,
    "ActiveMax": None,
    "ActiveMin": None,
    "IdleMean": None,
    "IdleStd": None,
    "IdleMax": None,
    "IdleMin": None,
}


def map_flow_to_features(flow_data: Dict[str, Any]) -> np.ndarray:
    """
    Map NFStream flow data to CIC-IDS feature vector.
    
    Args:
        flow_data: Dictionary of flow statistics from NFStream
    
    Returns:
        numpy array of shape (70,) matching feature_list order
    """
    if not network_ml_model.loaded:
        return np.array([])
    
    feature_list = network_ml_model.feature_list
    median_map = network_ml_model.median_map
    
    features = np.zeros(len(feature_list), dtype=np.float64)
    
    for i, feature_name in enumerate(feature_list):
        # Try to map from NFStream data
        nfstream_field = NFSTREAM_TO_CIC_MAP.get(feature_name)
        value = None
        
        if nfstream_field and nfstream_field in flow_data:
            value = flow_data[nfstream_field]
            
            # Special handling for FlowDuration (ms to us)
            if feature_name == "FlowDuration" and value is not None:
                value = value * 1000  # Convert ms to microseconds
        
        # Compute derived features
        if value is None:
            if feature_name == "FlowBytes/s":
                duration_ms = flow_data.get("bidirectional_duration_ms", 0)
                total_bytes = flow_data.get("bidirectional_bytes", 0)
                if duration_ms > 0:
                    value = (total_bytes / duration_ms) * 1000  # bytes per second
                    
            elif feature_name == "FlowPackets/s":
                duration_ms = flow_data.get("bidirectional_duration_ms", 0)
                total_packets = flow_data.get("bidirectional_packets", 0)
                if duration_ms > 0:
                    value = (total_packets / duration_ms) * 1000  # packets per second
                    
            elif feature_name == "FwdPackets/s":
                duration_ms = flow_data.get("bidirectional_duration_ms", 0)
                fwd_packets = flow_data.get("src2dst_packets", 0)
                if duration_ms > 0:
                    value = (fwd_packets / duration_ms) * 1000
                    
            elif feature_name == "BwdPackets/s":
                duration_ms = flow_data.get("bidirectional_duration_ms", 0)
                bwd_packets = flow_data.get("dst2src_packets", 0)
                if duration_ms > 0:
                    value = (bwd_packets / duration_ms) * 1000
                    
            elif feature_name == "Down/UpRatio":
                fwd_packets = flow_data.get("src2dst_packets", 0)
                bwd_packets = flow_data.get("dst2src_packets", 0)
                if fwd_packets > 0:
                    value = bwd_packets / fwd_packets
                else:
                    value = 0
                    
            elif feature_name == "AveragePacketSize":
                total_bytes = flow_data.get("bidirectional_bytes", 0)
                total_packets = flow_data.get("bidirectional_packets", 0)
                if total_packets > 0:
                    value = total_bytes / total_packets
                    
            elif feature_name == "AvgFwdSegmentSize":
                value = flow_data.get("src2dst_mean_ps", None)
                
            elif feature_name == "AvgBwdSegmentSize":
                value = flow_data.get("dst2src_mean_ps", None)
                
            elif feature_name == "PacketLengthVariance":
                std = flow_data.get("bidirectional_stddev_ps", None)
                if std is not None:
                    value = std ** 2
        
        # Use median as fallback
        if value is None:
            value = median_map.get(feature_name, 0.0)
        
        # Handle NaN/Inf
        if not np.isfinite(value):
            value = median_map.get(feature_name, 0.0)
        
        features[i] = value
    
    return features


def preprocess_features(features: np.ndarray) -> np.ndarray:
    """
    Apply preprocessing: fill NaN with median, clip extreme values.
    """
    if not network_ml_model.loaded:
        return features
    
    feature_list = network_ml_model.feature_list
    median_map = network_ml_model.median_map
    columns_to_clip = network_ml_model.columns_to_clip
    
    # Replace NaN/Inf with median
    for i, feature_name in enumerate(feature_list):
        if not np.isfinite(features[i]):
            features[i] = median_map.get(feature_name, 0.0)
    
    # Clip extreme values for specified columns
    # Use 1st and 99th percentile-like thresholds (approximated)
    for i, feature_name in enumerate(feature_list):
        if feature_name in columns_to_clip:
            median_val = median_map.get(feature_name, 0.0)
            # Clip to 10x median as a safe upper bound
            max_val = max(median_val * 10, 1e6)
            features[i] = np.clip(features[i], 0, max_val)
    
    return features
