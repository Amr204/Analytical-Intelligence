"""
Analytical-Intelligence v1 - Model Loaders
Gracefully loads ML models with fallback behavior.

Key fixes:
- Network RF predict(): robust handling for sklearn model.classes_ that may be STRINGS (e.g., 'Normal Traffic')
  OR numeric class IDs (e.g., 0..n-1). Avoid int('Normal Traffic') crash.
- Pass feature names to sklearn via pandas.DataFrame to keep correct order and remove warnings.
"""

from __future__ import annotations

import os
import json
import logging
from typing import Optional, Dict, Any, Tuple, Union, List

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
        self.threshold: float = 0.8
        self.loaded: bool = False
    
    def load(self, model_path: str) -> bool:
        """Load the SSH LSTM model from joblib."""
        try:
            import joblib
            from tensorflow.keras.models import model_from_json
            
            if not os.path.exists(model_path):
                logger.warning(f"SSH LSTM model not found at {model_path}")
                self.model = None
                self.loaded = False
                return False
        
            bundle = joblib.load(model_path)
        
            # Extract components
            model_json = bundle.get("model_json")
            weights = bundle.get("weights")
        
            if not model_json or not weights:
                raise ValueError("Invalid SSH LSTM model bundle")
        
            self.model = model_from_json(model_json)
            self.model.set_weights(weights)
        
            self.token2id = bundle.get("token2id", {})
            self.window_size = bundle.get("window_size", 10)
            self.stride = bundle.get("stride", 1)
            self.fail_threshold = bundle.get("fail_threshold", 5)
            self.time_window_sec = bundle.get("time_window_sec", 300)
            # Use configured threshold (defaults to 0.8) to reduce false positives
            self.threshold = settings.ssh_ml_threshold
        
            self.loaded = True
            logger.info(f"SSH LSTM model loaded successfully from {model_path}")
            logger.info(f"  - Tokens: {len(self.token2id)}")
            logger.info(f"  - Window size: {self.window_size}")
            logger.info(f"  - Threshold: {self.threshold}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to load SSH LSTM model: {e}")
            self.model = None
            self.loaded = False
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
# Global Model Instances
# =====================================================

ssh_lstm_model = SSHLSTMModel()


def load_all_models():
    """Load all ML models at startup."""
    logger.info("Loading ML models...")
    
    # Load SSH LSTM
    ssh_loaded = ssh_lstm_model.load(settings.ssh_model_path)
    if not ssh_loaded:
        logger.warning("SSH LSTM model not loaded - SSH detection will be limited")
    
    return ssh_loaded


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
            "loaded": False,
            "status": "REMOVED"
        }
    }
