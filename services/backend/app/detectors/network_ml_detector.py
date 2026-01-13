"""
Analytical-Intelligence v1 - Network ML Detector
Classifies network flows using the trained ML model.
"""

import logging
from typing import Dict, Any, Optional, Tuple

import numpy as np

from app.models_loader import network_ml_model
from app.detectors.network_feature_mapper import map_flow_to_features, preprocess_features
from app.detectors.severity import get_network_ml_severity
from app.config import settings

logger = logging.getLogger(__name__)


def analyze_flow(flow_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Analyze a network flow using the ML model.
    
    Args:
        flow_data: Flow statistics from NFStream
    
    Returns:
        Detection dict if attack detected, None otherwise
    """
    if not network_ml_model.loaded:
        logger.debug("Network ML model not loaded, skipping flow analysis")
        return None
    
    try:
        # Map flow to feature vector
        features = map_flow_to_features(flow_data)
        
        if len(features) == 0:
            return None
        
        # Preprocess
        features = preprocess_features(features)
        
        # Predict
        label, score, proba = network_ml_model.predict(features)

        label_norm = (label or "").strip().upper()

        # Reject benign/unknown/empty
        if label_norm in ("BENIGN", "UNKNOWN", ""):
            return None

        # Reject labels not in known label map (when model loaded)
        known = set(network_ml_model.label_map.keys()) if network_ml_model.loaded else set()
        if known and label not in known:
            return None

        logger.debug(f"Flow prediction: {label} (score={score:.3f})")

        # Only create detection for non-benign with sufficient confidence
        if label_norm != "BENIGN" and score >= settings.network_ml_threshold:
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
                "model_name": "network_ml",
                "label": label,
                "score": score,
                "severity": severity,
                "details": details
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Flow analysis error: {e}")
        return None


def get_model_info() -> Dict[str, Any]:
    """Get network ML model information."""
    return {
        "loaded": network_ml_model.loaded,
        "features_count": len(network_ml_model.feature_list),
        "labels": list(network_ml_model.label_map.keys()),
        "threshold": settings.network_ml_threshold,
    }
