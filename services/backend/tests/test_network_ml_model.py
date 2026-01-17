"""
Unit/Integration tests for Network RF Model prediction.
Tests sklearn Random Forest model with predict_proba and allowlist filtering.
"""

import numpy as np
import pytest
from unittest.mock import MagicMock, patch


class TestNetworkMLModelPredict:
    """Tests for NetworkMLModel.predict() with Random Forest."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Reset the module to get fresh instances
        import importlib
        import app.models_loader as ml
        importlib.reload(ml)
        self.NetworkMLModel = ml.NetworkMLModel
    
    def test_predict_with_sklearn_rf_model(self):
        """Test prediction with sklearn RandomForest that has predict_proba."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {0: "Normal Traffic", 1: "DDoS", 2: "DoS"}
        model_wrapper.feature_list = ["feat1", "feat2", "feat3"]
        model_wrapper.benign_label = "Normal Traffic"
        
        # Mock sklearn-style model with predict_proba
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.1, 0.8, 0.1]])
        model_wrapper.model = mock_model
        
        features = np.array([1.0, 2.0, 3.0])
        label, score, proba = model_wrapper.predict(features)
        
        assert label == "DDoS"
        assert abs(score - 0.8) < 0.01
        assert len(proba) == 3
        mock_model.predict_proba.assert_called_once()
    
    def test_predict_multiclass(self):
        """Test prediction with multiclass RF (7 classes like production model)."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {
            0: "Normal Traffic", 
            1: "Port Scanning", 
            2: "Brute Force",
            3: "DoS",
            4: "DDoS",
            5: "Bots",
            6: "Web Attacks"
        }
        model_wrapper.feature_list = ["feat1", "feat2", "feat3"]
        model_wrapper.benign_label = "Normal Traffic"
        
        # Simulate multiclass prediction with DDoS as highest
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.05, 0.02, 0.03, 0.1, 0.7, 0.05, 0.05]])
        model_wrapper.model = mock_model
        
        features = np.array([1.0, 2.0, 3.0])
        label, score, proba = model_wrapper.predict(features)
        
        assert label == "DDoS"
        assert abs(score - 0.7) < 0.01
        assert len(proba) == 7
    
    def test_predict_benign(self):
        """Test prediction returns Normal Traffic for benign flows."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {0: "Normal Traffic", 1: "DDoS", 2: "DoS"}
        model_wrapper.feature_list = ["feat1", "feat2", "feat3"]
        model_wrapper.benign_label = "Normal Traffic"
        
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.95, 0.03, 0.02]])
        model_wrapper.model = mock_model
        
        features = np.array([1.0, 2.0, 3.0])
        label, score, proba = model_wrapper.predict(features)
        
        assert label == "Normal Traffic"
        assert abs(score - 0.95) < 0.01
    
    def test_predict_not_loaded(self):
        """Test prediction returns UNKNOWN when model not loaded."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = False
        
        features = np.array([1.0, 2.0, 3.0])
        label, score, proba = model_wrapper.predict(features)
        
        assert label == "UNKNOWN"
        assert score == 0.0
        assert len(proba) == 0
    
    def test_predict_handles_1d_features(self):
        """Test that 1D features are correctly reshaped."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {0: "Normal Traffic", 1: "DDoS"}
        model_wrapper.feature_list = ["feat1", "feat2", "feat3"]
        
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])
        model_wrapper.model = mock_model
        
        # Pass 1D array
        features = np.array([1.0, 2.0, 3.0])
        label, score, proba = model_wrapper.predict(features)
        
        # Verify features were reshaped to 2D
        call_args = mock_model.predict_proba.call_args[0][0]
        assert call_args.ndim == 2
        assert call_args.shape == (1, 3)
    
    def test_predict_exception_handling(self):
        """Test that exceptions are handled gracefully."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {0: "Normal Traffic", 1: "DDoS"}
        
        mock_model = MagicMock()
        mock_model.predict_proba.side_effect = RuntimeError("Model error")
        model_wrapper.model = mock_model
        
        features = np.array([1.0, 2.0, 3.0])
        label, score, proba = model_wrapper.predict(features)
        
        # Should return defaults on error
        assert label == "UNKNOWN"
        assert score == 0.0
        assert len(proba) == 0


class TestExtractLabelAndScore:
    """Tests for the _extract_label_and_score helper method."""
    
    def setup_method(self):
        """Set up test fixtures."""
        import app.models_loader as ml
        self.model = ml.NetworkMLModel()
    
    def test_multiclass_extraction(self):
        """Test extraction for multiclass (>2 classes)."""
        proba = np.array([0.1, 0.6, 0.3])
        label_id, score = self.model._extract_label_and_score(proba)
        
        assert label_id == 1
        assert abs(score - 0.6) < 0.01
    
    def test_binary_above_threshold(self):
        """Test binary extraction above threshold."""
        proba = np.array([0.2, 0.8])
        label_id, score = self.model._extract_label_and_score(proba)
        
        assert label_id == 1
        assert abs(score - 0.8) < 0.01
    
    def test_binary_below_threshold(self):
        """Test binary extraction below threshold."""
        proba = np.array([0.7, 0.3])
        label_id, score = self.model._extract_label_and_score(proba)
        
        assert label_id == 0
        assert abs(score - 0.7) < 0.01
    
    def test_binary_custom_threshold(self):
        """Test binary extraction with custom threshold."""
        proba = np.array([0.3, 0.7])
        label_id, score = self.model._extract_label_and_score(proba, threshold=0.8)
        
        # 0.7 is below 0.8 threshold, so should be class 0
        assert label_id == 0


class TestAllowlistFiltering:
    """Tests for label allowlist filtering in network_ml_detector."""
    
    def test_allowed_label_creates_detection(self):
        """Test that allowed labels (DDoS) create detection."""
        from app.detectors.network_ml_detector import is_label_allowed
        
        # These should be allowed
        assert is_label_allowed("DDoS") == True
        assert is_label_allowed("DoS") == True
        assert is_label_allowed("Port Scanning") == True
        assert is_label_allowed("Brute Force") == True
    
    def test_non_allowed_label_filtered(self):
        """Test that non-allowed labels (Bots, Web Attacks) are filtered."""
        from app.detectors.network_ml_detector import is_label_allowed
        
        # These should NOT be allowed
        assert is_label_allowed("Bots") == False
        assert is_label_allowed("Web Attacks") == False
        assert is_label_allowed("Normal Traffic") == False
    
    def test_get_allowed_labels_returns_list(self):
        """Test get_allowed_labels returns proper list."""
        from app.detectors.network_ml_detector import get_allowed_labels
        
        allowed = get_allowed_labels()
        assert isinstance(allowed, list)
        assert len(allowed) == 4
        assert "DDoS" in allowed
        assert "DoS" in allowed
        assert "Port Scanning" in allowed
        assert "Brute Force" in allowed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
