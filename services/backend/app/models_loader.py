"""
Mini-SIEM v1 - Model Loaders
Gracefully loads ML models with fallback behavior.
"""

import os
import json
import logging
from typing import Optional, Dict, Any, Tuple

import numpy as np

from app.config import settings

logger = logging.getLogger(__name__)


# =====================================================
# SSH LSTM Model Loader
# =====================================================

class SSHLSTMModel:
    """SSH LSTM model wrapper."""
    
    def __init__(self):
        self.model = None
        self.token2id: Dict[str, int] = {}
        self.window_size: int = 10
        self.stride: int = 1
        self.fail_threshold: int = 5
        self.time_window_sec: int = 300
        self.threshold: float = 0.5
        self.loaded: bool = False
    
    def load(self, model_path: str) -> bool:
        """Load the SSH LSTM model from joblib."""
        try:
            import joblib
            from tensorflow.keras.models import model_from_json
            
            if not os.path.exists(model_path):
                logger.warning(f"SSH LSTM model not found at {model_path}")
                return False
            
            bundle = joblib.load(model_path)
            
            # Extract components
            model_json = bundle.get("model_json")
            weights = bundle.get("weights")
            
            if model_json and weights:
                self.model = model_from_json(model_json)
                self.model.set_weights(weights)
            
            self.token2id = bundle.get("token2id", {})
            self.window_size = bundle.get("window_size", 10)
            self.stride = bundle.get("stride", 1)
            self.fail_threshold = bundle.get("fail_threshold", 5)
            self.time_window_sec = bundle.get("time_window_sec", 300)
            self.threshold = bundle.get("threshold", 0.5)
            
            self.loaded = True
            logger.info(f"SSH LSTM model loaded successfully from {model_path}")
            logger.info(f"  - Tokens: {len(self.token2id)}")
            logger.info(f"  - Window size: {self.window_size}")
            logger.info(f"  - Threshold: {self.threshold}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load SSH LSTM model: {e}")
            return False
    
    def predict(self, token_sequence: np.ndarray) -> Tuple[float, bool]:
        """
        Predict anomaly score for a token sequence.
        Returns (score, is_anomaly).
        """
        if not self.loaded or self.model is None:
            return 0.0, False
        
        try:
            # Ensure correct shape
            if len(token_sequence) < self.window_size:
                # Pad with zeros
                padded = np.zeros(self.window_size, dtype=np.int32)
                padded[-len(token_sequence):] = token_sequence
                token_sequence = padded
            
            # Take last window_size tokens
            X = token_sequence[-self.window_size:].reshape(1, self.window_size, 1)
            
            # Predict
            pred = self.model.predict(X, verbose=0)
            score = float(np.max(pred))
            is_anomaly = score >= self.threshold
            
            return score, is_anomaly
            
        except Exception as e:
            logger.error(f"SSH LSTM prediction error: {e}")
            return 0.0, False


# =====================================================
# Network ML Model Loader
# =====================================================

class NetworkMLModel:
    """Network ML model wrapper."""
    
    def __init__(self):
        self.model = None
        self.feature_list: list = []
        self.label_map: Dict[str, int] = {}
        self.inverse_label_map: Dict[int, str] = {}
        self.median_map: Dict[str, float] = {}
        self.columns_to_clip: list = []
        self.loaded: bool = False
    
    def load(
        self,
        model_path: str,
        features_path: str,
        labels_path: str,
        preprocess_path: str
    ) -> bool:
        """Load the network ML model and its artifacts."""
        try:
            import joblib
            
            # Check all files exist
            for path in [model_path, features_path, labels_path, preprocess_path]:
                if not os.path.exists(path):
                    logger.warning(f"Network model file not found: {path}")
                    return False
            
            # Load model
            self.model = joblib.load(model_path)
            
            # Load feature list
            with open(features_path, "r") as f:
                self.feature_list = json.load(f)
            
            # Load label map
            with open(labels_path, "r") as f:
                self.label_map = json.load(f)
                self.inverse_label_map = {v: k for k, v in self.label_map.items()}
            
            # Load preprocess config
            with open(preprocess_path, "r") as f:
                preprocess = json.load(f)
                self.median_map = preprocess.get("median_map", {})
                self.columns_to_clip = preprocess.get("columns_to_clip", [])
            
            self.loaded = True
            logger.info(f"Network ML model loaded successfully")
            logger.info(f"  - Features: {len(self.feature_list)}")
            logger.info(f"  - Labels: {list(self.label_map.keys())}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load Network ML model: {e}")
            return False
    
    def predict(self, features: np.ndarray) -> Tuple[str, float, np.ndarray]:
        """
        Predict attack class for feature vector.
        Returns (label_name, confidence, all_probabilities).
        """
        if not self.loaded or self.model is None:
            return "UNKNOWN", 0.0, np.array([])
        
        try:
            # Reshape if needed
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            # Get probabilities
            proba = self.model.predict_proba(features)[0]
            label_id = int(np.argmax(proba))
            score = float(proba[label_id])
            label_name = self.inverse_label_map.get(label_id, "UNKNOWN")
            
            return label_name, score, proba
            
        except Exception as e:
            logger.error(f"Network ML prediction error: {e}")
            return "UNKNOWN", 0.0, np.array([])


# =====================================================
# Global Model Instances
# =====================================================

ssh_lstm_model = SSHLSTMModel()
network_ml_model = NetworkMLModel()


def load_all_models():
    """Load all ML models at startup."""
    logger.info("Loading ML models...")
    
    # Load SSH LSTM
    ssh_loaded = ssh_lstm_model.load(settings.ssh_model_path)
    if not ssh_loaded:
        logger.warning("SSH LSTM model not loaded - SSH detection will be limited")
    
    # Load Network ML
    network_loaded = network_ml_model.load(
        settings.network_model_path,
        settings.network_features_path,
        settings.network_labels_path,
        settings.network_preprocess_path
    )
    if not network_loaded:
        logger.warning("Network ML model not loaded - flow classification will be disabled")
    
    return ssh_loaded, network_loaded


def get_models_status() -> Dict[str, Any]:
    """Get status of all loaded models."""
    return {
        "ssh_lstm": {
            "loaded": ssh_lstm_model.loaded,
            "tokens": len(ssh_lstm_model.token2id) if ssh_lstm_model.loaded else 0,
            "window_size": ssh_lstm_model.window_size,
            "threshold": ssh_lstm_model.threshold,
            "fail_threshold": ssh_lstm_model.fail_threshold,
            "time_window_sec": ssh_lstm_model.time_window_sec,
        },
        "network_ml": {
            "loaded": network_ml_model.loaded,
            "features_count": len(network_ml_model.feature_list) if network_ml_model.loaded else 0,
            "labels": list(network_ml_model.label_map.keys()) if network_ml_model.loaded else [],
            "labels_count": len(network_ml_model.label_map) if network_ml_model.loaded else 0,
        }
    }
