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
        self.threshold: float = 0.5
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
            self.threshold = bundle.get("threshold", 0.5)
        
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
# Network RF Model Loader (Random Forest)
# =====================================================

LabelKey = Union[int, str, np.integer, np.str_]

class NetworkMLModel:
    """
    Network ML model wrapper for Random Forest classifier.
    Trained on CIC-IDS2017 dataset with 52 features.
    """
    
    def __init__(self):
        self.model = None
        self.feature_list: List[str] = []
        self.label_map: Dict[str, int] = {}
        self.inverse_label_map: Dict[int, str] = {}
        self.median_map: Dict[str, float] = {}
        self.columns_to_clip: List[str] = []
        self.metrics: Dict[str, Any] = {}
        self.loaded: bool = False

        # Benign label for RF model (string label)
        self.benign_label: str = "Normal Traffic"

        # Keep a copy for debugging
        self._classes: Optional[List[Any]] = None
    
    def load(
        self,
        model_path: str,
        features_path: str,
        labels_path: str,
        preprocess_path: str
    ) -> bool:
        """Load the network RF model and its artifacts."""
        try:
            import joblib
            
            # Check required files exist
            if not os.path.exists(model_path):
                logger.warning(f"Network RF model not found: {model_path}")
                return False
            
            if not os.path.exists(features_path):
                logger.warning(f"Network RF features not found: {features_path}")
                return False
                
            if not os.path.exists(labels_path):
                logger.warning(f"Network RF labels not found: {labels_path}")
                return False
            
            # Load model (sklearn RandomForest with predict_proba)
            self.model = joblib.load(model_path)
            
            # Verify model has predict_proba (required for confidence scores)
            if not hasattr(self.model, "predict_proba"):
                logger.error("Loaded Network RF model does not have predict_proba method")
                return False
            
            # Load feature list (52 features with spaces in names)
            with open(features_path, "r", encoding="utf-8") as f:
                self.feature_list = json.load(f)
            if not isinstance(self.feature_list, list) or not all(isinstance(x, str) for x in self.feature_list):
                raise ValueError("Invalid feature_list.json (expected list[str])")
            
            # Load label map (optional: used if model outputs numeric IDs)
            with open(labels_path, "r", encoding="utf-8") as f:
                self.label_map = json.load(f)
                self.inverse_label_map = {int(v): k for k, v in self.label_map.items()}

            # If benign label exists in label_map, align benign_label string
            if "Normal Traffic" in self.label_map:
                self.benign_label = "Normal Traffic"

            # Load preprocess config (optional)
            if os.path.exists(preprocess_path):
                with open(preprocess_path, "r", encoding="utf-8") as f:
                    preprocess = json.load(f)
                    self.median_map = preprocess.get("median_map", {}) or {}
                    self.columns_to_clip = preprocess.get("columns_to_clip", []) or []
            else:
                logger.info("No preprocess config found, using defaults")
                self.median_map = {}
                self.columns_to_clip = []
            
            # Load metrics (optional - for UI display)
            metrics_path = settings.network_metrics_path
            if os.path.exists(metrics_path):
                with open(metrics_path, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            
            # Cache model classes for debug
            classes = getattr(self.model, "classes_", None)
            if classes is not None:
                try:
                    self._classes = list(classes)
                except Exception:
                    self._classes = None
            
            self.loaded = True
            logger.info("Network RF model loaded successfully")
            logger.info(f"  - Features: {len(self.feature_list)}")
            logger.info(f"  - Labels (from label_map): {list(self.label_map.keys())}")
            logger.info(f"  - Benign label: {self.benign_label}")
            if self._classes is not None:
                logger.info(f"  - sklearn classes_: {self._classes}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load Network RF model: {e}")
            self.model = None
            self.loaded = False
            return False
    
    def predict(self, features: np.ndarray) -> Tuple[str, float, np.ndarray]:
        """
        Predict attack class for feature vector.
        Returns (label_name, confidence, all_probabilities).

        Robust to sklearn models where:
        - model.classes_ can be numeric IDs (0..n-1), OR
        - model.classes_ can be string labels ('Normal Traffic', 'DoS', ...)

        Also passes feature names via pandas.DataFrame (when available)
        to preserve correct order and remove sklearn warning.
        """
        if not self.loaded or self.model is None:
            return "UNKNOWN", 0.0, np.array([])

        try:
            # Ensure 1D vector
            if features.ndim == 2 and features.shape[0] == 1:
                row = features[0]
            elif features.ndim == 1:
                row = features
            else:
                # Unexpected shape
                row = features.reshape(-1)

            # Validate feature length
            if self.feature_list and len(row) != len(self.feature_list):
                logger.warning(
                    f"Network RF received feature vector length={len(row)} "
                    f"but expected={len(self.feature_list)}. "
                    "Prediction may be incorrect."
                )

            X = self._to_sklearn_input(row)

            # Predict probabilities
            proba = self.model.predict_proba(X)[0]
            if proba is None or len(proba) == 0:
                return "UNKNOWN", 0.0, np.array([])

            classes = getattr(self.model, "classes_", None)
            label_key, score = self._extract_label_and_score(proba, classes)
            label_name = self._label_from_key(label_key)

            return label_name, score, proba

        except Exception as e:
            logger.error(f"Network RF prediction error: {e}")
            return "UNKNOWN", 0.0, np.array([])

    def _to_sklearn_input(self, row: np.ndarray):
        """
        Convert a 1D feature row into a sklearn-friendly 2D input.
        Prefer pandas.DataFrame with column names to preserve order.
        """
        # Try pandas to preserve feature names (removes sklearn warning)
        try:
            import pandas as pd  # type: ignore
            if self.feature_list:
                return pd.DataFrame([row], columns=self.feature_list)
        except Exception:
            pass

        # Fallback: numpy 2D
        return np.asarray([row], dtype=float)

    def _extract_label_and_score(
        self,
        proba: np.ndarray,
        classes: Optional[np.ndarray] = None,
        threshold: float = 0.5
    ) -> Tuple[LabelKey, float]:
        """
        Extract label key (class value) + confidence score from probability array.

        For multiclass: uses argmax.
        For binary: uses threshold (kept for completeness, although your RF is multiclass).
        """
        num_classes = len(proba)

        if num_classes == 2:
            score_pos = float(proba[1])
            is_pos = score_pos >= threshold
            idx = 1 if is_pos else 0
            score = score_pos if is_pos else (1.0 - score_pos)

            if classes is not None and len(classes) == 2:
                return classes[idx], score
            return idx, score

        # Multiclass
        argmax_idx = int(np.argmax(proba))
        score = float(proba[argmax_idx])

        if classes is not None and len(classes) == len(proba):
            return classes[argmax_idx], score

        # Fallback: class key = argmax index
        return argmax_idx, score

    def _label_from_key(self, label_key: LabelKey) -> str:
        """
        Convert sklearn class value into final label string.

        If model.classes_ are strings -> return them directly.
        If model.classes_ are numeric -> map via inverse_label_map.
        """
        # If it's already a string label, return it
        if isinstance(label_key, (str, np.str_)):
            return str(label_key)

        # Numeric path
        try:
            label_id = int(label_key)  # works for numpy ints too
            return self.inverse_label_map.get(label_id, str(label_id))
        except Exception:
            # Last resort
            return str(label_key)


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
    
    # Load Network RF
    network_loaded = network_ml_model.load(
        settings.network_model_path,
        settings.network_features_path,
        settings.network_labels_path,
        settings.network_preprocess_path
    )
    if not network_loaded:
        logger.warning("Network RF model not loaded - flow classification will be disabled")
    
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
            "benign_label": network_ml_model.benign_label,
            "metrics": network_ml_model.metrics if network_ml_model.loaded else {},
        }
    }
