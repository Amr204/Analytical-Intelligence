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
        mock_model.classes_ = np.array([0, 1, 2])  # Standard ordering
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
        mock_model.classes_ = np.array([0, 1, 2, 3, 4, 5, 6])
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
        mock_model.classes_ = np.array([0, 1, 2])
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
        mock_model.classes_ = np.array([0, 1])
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


class TestClassesMapping:
    """Tests for correct handling of sklearn model.classes_ ordering.
    
    CRITICAL: sklearn's predict_proba returns columns in model.classes_ order,
    which may NOT be [0, 1, 2, ...]. The argmax index must be mapped through
    model.classes_ to get the actual class ID.
    """
    
    def setup_method(self):
        """Set up test fixtures."""
        import importlib
        import app.models_loader as ml
        importlib.reload(ml)
        self.NetworkMLModel = ml.NetworkMLModel
    
    def test_non_sequential_classes_ordering(self):
        """Test that model.classes_ = [4, 1, 0, 2, 3] maps correctly.
        
        This is the root cause of false DDoS: if classes_ is reordered,
        argmax index doesn't directly map to label_id.
        """
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {
            0: "Normal Traffic",
            1: "Port Scanning",
            2: "Brute Force", 
            3: "DoS",
            4: "DDoS"
        }
        model_wrapper.feature_list = ["feat1"]
        
        mock_model = MagicMock()
        # Proba: class at index 0 (which is class_id=4 DDoS) has highest prob
        # But if we DON'T use classes_, we'd incorrectly return label for id=0 ("Normal Traffic")
        mock_model.predict_proba.return_value = np.array([[0.9, 0.02, 0.03, 0.03, 0.02]])
        mock_model.classes_ = np.array([4, 1, 0, 2, 3])  # Non-sequential!
        model_wrapper.model = mock_model
        
        features = np.array([1.0])
        label, score, proba = model_wrapper.predict(features)
        
        # argmax=0, but classes_[0]=4, so label_id=4 => "DDoS"
        assert label == "DDoS", f"Expected DDoS but got {label}"
        assert abs(score - 0.9) < 0.01
    
    def test_reversed_classes_ordering(self):
        """Test with completely reversed classes_ order."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {
            0: "Normal Traffic",
            1: "Port Scanning",
            2: "DoS"
        }
        model_wrapper.feature_list = ["feat1"]
        
        mock_model = MagicMock()
        # Proba columns: [class_2, class_1, class_0] due to reversed classes_
        # High prob at index 1 => class_id = 1 => "Port Scanning"
        mock_model.predict_proba.return_value = np.array([[0.1, 0.8, 0.1]])
        mock_model.classes_ = np.array([2, 1, 0])  # Reversed
        model_wrapper.model = mock_model
        
        features = np.array([1.0])
        label, score, proba = model_wrapper.predict(features)
        
        # argmax=1, classes_[1]=1 => "Port Scanning"
        assert label == "Port Scanning"
        assert abs(score - 0.8) < 0.01
    
    def test_classes_none_fallback(self):
        """Test fallback when model doesn't have classes_ attribute."""
        model_wrapper = self.NetworkMLModel()
        model_wrapper.loaded = True
        model_wrapper.inverse_label_map = {0: "Normal", 1: "Attack"}
        model_wrapper.feature_list = ["feat1"]
        
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.3, 0.7]])
        # Simulate model without classes_ attribute
        del mock_model.classes_
        model_wrapper.model = mock_model
        
        features = np.array([1.0])
        label, score, proba = model_wrapper.predict(features)
        
        # Without classes_, falls back to argmax directly
        assert label == "Attack"
        assert abs(score - 0.7) < 0.01


class TestExtractLabelAndScore:
    """Tests for the _extract_label_and_score helper method."""
    
    def setup_method(self):
        """Set up test fixtures."""
        import app.models_loader as ml
        self.model = ml.NetworkMLModel()
    
    def test_multiclass_extraction(self):
        """Test extraction for multiclass (>2 classes)."""
        proba = np.array([0.1, 0.6, 0.3])
        classes = np.array([0, 1, 2])
        label_id, score = self.model._extract_label_and_score(proba, classes)
        
        assert label_id == 1
        assert abs(score - 0.6) < 0.01
    
    def test_multiclass_with_reordered_classes(self):
        """Test multiclass extraction with non-standard classes order."""
        proba = np.array([0.1, 0.6, 0.3])  # Index 1 is max
        classes = np.array([2, 0, 1])  # classes_[1] = 0
        label_id, score = self.model._extract_label_and_score(proba, classes)
        
        # argmax=1, classes[1]=0, so label_id should be 0
        assert label_id == 0
        assert abs(score - 0.6) < 0.01
    
    def test_binary_above_threshold(self):
        """Test binary extraction above threshold."""
        proba = np.array([0.2, 0.8])
        classes = np.array([0, 1])
        label_id, score = self.model._extract_label_and_score(proba, classes)
        
        assert label_id == 1
        assert abs(score - 0.8) < 0.01
    
    def test_binary_below_threshold(self):
        """Test binary extraction below threshold."""
        proba = np.array([0.7, 0.3])
        classes = np.array([0, 1])
        label_id, score = self.model._extract_label_and_score(proba, classes)
        
        assert label_id == 0
        assert abs(score - 0.7) < 0.01
    
    def test_binary_custom_threshold(self):
        """Test binary extraction with custom threshold."""
        proba = np.array([0.3, 0.7])
        classes = np.array([0, 1])
        label_id, score = self.model._extract_label_and_score(proba, classes, threshold=0.8)
        
        # 0.7 is below 0.8 threshold, so should be class 0
        assert label_id == 0


class TestFeatureMapperDurationHandling:
    """Tests for duration_ms==0 and rate feature handling."""
    
    def test_zero_duration_rate_features_are_zero(self):
        """When duration_ms=0, rate features should be 0, not infinity."""
        import os
        os.environ["MIN_FLOW_DURATION_MS"] = "50"
        
        # Reload to pick up env var
        import importlib
        import app.detectors.network_feature_mapper as mapper
        importlib.reload(mapper)
        
        from app.models_loader import network_ml_model
        
        # Mock the model as loaded with minimal feature list
        network_ml_model.loaded = True
        network_ml_model.feature_list = [
            "Flow Duration",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Total Fwd Packets"
        ]
        network_ml_model.median_map = {}
        
        flow_data = {
            "bidirectional_duration_ms": 0,  # Zero duration!
            "bidirectional_bytes": 1000,
            "bidirectional_packets": 10,
            "src2dst_packets": 5,
        }
        
        features, debug_info = mapper.map_flow_to_features(flow_data)
        
        # Flow Duration (index 0) should be 0 (0ms * 1000 = 0µs)
        assert features[0] == 0.0
        
        # Flow Bytes/s (index 1) should be 0, not inf
        assert features[1] == 0.0
        assert np.isfinite(features[1])
        
        # Flow Packets/s (index 2) should be 0, not inf
        assert features[2] == 0.0
        assert np.isfinite(features[2])
        
        # rate_safe should be False
        assert debug_info.get("rate_safe") == False
    
    def test_small_duration_rate_features_are_zero(self):
        """When duration_ms < MIN_FLOW_DURATION_MS, rate features should be 0."""
        import os
        os.environ["MIN_FLOW_DURATION_MS"] = "50"
        
        import importlib
        import app.detectors.network_feature_mapper as mapper
        importlib.reload(mapper)
        
        from app.models_loader import network_ml_model
        
        network_ml_model.loaded = True
        network_ml_model.feature_list = ["Flow Bytes/s", "Flow Packets/s"]
        network_ml_model.median_map = {}
        
        flow_data = {
            "bidirectional_duration_ms": 10,  # Below 50ms threshold
            "bidirectional_bytes": 1000,
            "bidirectional_packets": 10,
        }
        
        features, debug_info = mapper.map_flow_to_features(flow_data)
        
        # Both rate features should be 0
        assert features[0] == 0.0  # Flow Bytes/s
        assert features[1] == 0.0  # Flow Packets/s
        assert debug_info.get("rate_safe") == False
    
    def test_normal_duration_rate_features_calculated(self):
        """When duration_ms >= MIN_FLOW_DURATION_MS, rate features should be calculated."""
        import os
        os.environ["MIN_FLOW_DURATION_MS"] = "50"
        
        import importlib
        import app.detectors.network_feature_mapper as mapper
        importlib.reload(mapper)
        
        from app.models_loader import network_ml_model
        
        network_ml_model.loaded = True
        network_ml_model.feature_list = ["Flow Bytes/s", "Flow Packets/s"]
        network_ml_model.median_map = {}
        
        flow_data = {
            "bidirectional_duration_ms": 1000,  # 1 second, above threshold
            "bidirectional_bytes": 1000,
            "bidirectional_packets": 100,
        }
        
        features, debug_info = mapper.map_flow_to_features(flow_data)
        
        # Rate features should be calculated: 1000 bytes / 1 sec = 1000 BPS
        assert abs(features[0] - 1000.0) < 0.01  # Flow Bytes/s
        assert abs(features[1] - 100.0) < 0.01   # Flow Packets/s
        assert debug_info.get("rate_safe") == True


class TestIATUnitConversion:
    """Tests for IAT milliseconds to microseconds conversion."""
    
    def test_iat_features_converted_to_microseconds(self):
        """Verify IAT features are converted from ms to µs (multiply by 1000)."""
        import importlib
        import app.detectors.network_feature_mapper as mapper
        importlib.reload(mapper)
        
        from app.models_loader import network_ml_model
        
        network_ml_model.loaded = True
        network_ml_model.feature_list = [
            "Flow IAT Mean",
            "Flow IAT Std", 
            "Fwd IAT Mean",
            "Bwd IAT Mean"
        ]
        network_ml_model.median_map = {}
        
        flow_data = {
            "bidirectional_mean_piat_ms": 10.0,   # 10ms
            "bidirectional_stddev_piat_ms": 5.0,  # 5ms
            "src2dst_mean_piat_ms": 8.0,          # 8ms
            "dst2src_mean_piat_ms": 12.0,         # 12ms
            "bidirectional_duration_ms": 1000,
        }
        
        features, _ = mapper.map_flow_to_features(flow_data)
        
        # All should be in microseconds (ms * 1000)
        assert abs(features[0] - 10000.0) < 0.01  # 10ms = 10000µs
        assert abs(features[1] - 5000.0) < 0.01   # 5ms = 5000µs
        assert abs(features[2] - 8000.0) < 0.01   # 8ms = 8000µs
        assert abs(features[3] - 12000.0) < 0.01  # 12ms = 12000µs


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


class TestLabelNormalization:
    """Tests for label normalization function."""
    
    def test_normalize_portscan_variants(self):
        """Test that PortScan variants are normalized."""
        from app.detectors.network_ml_detector import normalize_label
        
        assert normalize_label("PortScan") == "Port Scanning"
        assert normalize_label("portscans") == "Port Scanning"
        assert normalize_label("Port Scans") == "Port Scanning"
        assert normalize_label("Port Scanning") == "Port Scanning"
    
    def test_normalize_bruteforce_variants(self):
        """Test that BruteForce variants are normalized."""
        from app.detectors.network_ml_detector import normalize_label
        
        assert normalize_label("BruteForce") == "Brute Force"
        assert normalize_label("bruteforce") == "Brute Force"
        assert normalize_label("Brute-Force") == "Brute Force"
        assert normalize_label("Brute Force") == "Brute Force"
    
    def test_normalize_ddos_variants(self):
        """Test that DDoS case variants are normalized."""
        from app.detectors.network_ml_detector import normalize_label
        
        assert normalize_label("DDOS") == "DDoS"
        assert normalize_label("ddos") == "DDoS"
        assert normalize_label("DDoS") == "DDoS"
    
    def test_normalize_dos_variants(self):
        """Test that DoS case variants are normalized."""
        from app.detectors.network_ml_detector import normalize_label
        
        assert normalize_label("DOS") == "DoS"
        assert normalize_label("dos") == "DoS"
        assert normalize_label("DoS") == "DoS"
    
    def test_normalize_unknown_label_passthrough(self):
        """Test that unknown labels pass through unchanged (except stripping)."""
        from app.detectors.network_ml_detector import normalize_label
        
        assert normalize_label("  Normal Traffic  ") == "Normal Traffic"
        assert normalize_label("Bots") == "Bots"
        assert normalize_label("Web Attacks") == "Web Attacks"
    
    def test_normalize_empty_label(self):
        """Test that empty or None labels return empty string."""
        from app.detectors.network_ml_detector import normalize_label
        
        assert normalize_label("") == ""
        assert normalize_label("   ") == ""


class TestSafeClassToLabel:
    """Tests for _safe_class_to_label helper function."""
    
    def test_safe_class_with_string_classes(self):
        """Test safe mapping when model.classes_ are strings."""
        from app.detectors.network_ml_detector import _safe_class_to_label
        from app.models_loader import network_ml_model
        from unittest.mock import MagicMock
        
        # Save original state
        orig_loaded = network_ml_model.loaded
        orig_model = network_ml_model.model
        
        try:
            # Mock model with STRING classes
            mock_model = MagicMock()
            mock_model.classes_ = ["Normal Traffic", "DoS", "DDoS", "Port Scanning"]
            network_ml_model.model = mock_model
            network_ml_model.loaded = True
            
            assert _safe_class_to_label(0) == "Normal Traffic"
            assert _safe_class_to_label(1) == "DoS"
            assert _safe_class_to_label(2) == "DDoS"
            assert _safe_class_to_label(3) == "Port Scanning"
        finally:
            network_ml_model.loaded = orig_loaded
            network_ml_model.model = orig_model
    
    def test_safe_class_with_numeric_classes(self):
        """Test safe mapping when model.classes_ are numeric."""
        from app.detectors.network_ml_detector import _safe_class_to_label
        from app.models_loader import network_ml_model
        from unittest.mock import MagicMock
        import numpy as np
        
        # Save original state
        orig_loaded = network_ml_model.loaded
        orig_model = network_ml_model.model
        orig_inverse = network_ml_model.inverse_label_map
        
        try:
            # Mock model with NUMERIC classes
            mock_model = MagicMock()
            mock_model.classes_ = np.array([0, 1, 2, 3])
            network_ml_model.model = mock_model
            network_ml_model.loaded = True
            network_ml_model.inverse_label_map = {
                0: "Normal Traffic",
                1: "DoS",
                2: "DDoS", 
                3: "Port Scanning"
            }
            
            assert _safe_class_to_label(0) == "Normal Traffic"
            assert _safe_class_to_label(1) == "DoS"
            assert _safe_class_to_label(2) == "DDoS"
            assert _safe_class_to_label(3) == "Port Scanning"
        finally:
            network_ml_model.loaded = orig_loaded
            network_ml_model.model = orig_model
            network_ml_model.inverse_label_map = orig_inverse
    
    def test_safe_class_out_of_range(self):
        """Test that out-of-range indices return string of index."""
        from app.detectors.network_ml_detector import _safe_class_to_label
        from app.models_loader import network_ml_model
        from unittest.mock import MagicMock
        
        orig_loaded = network_ml_model.loaded
        orig_model = network_ml_model.model
        
        try:
            mock_model = MagicMock()
            mock_model.classes_ = ["A", "B"]
            network_ml_model.model = mock_model
            network_ml_model.loaded = True
            
            # Index 10 is out of range, should return "10"
            assert _safe_class_to_label(10) == "10"
        finally:
            network_ml_model.loaded = orig_loaded
            network_ml_model.model = orig_model
    
    def test_safe_class_no_classes_attribute(self):
        """Test fallback when model has no classes_ attribute."""
        from app.detectors.network_ml_detector import _safe_class_to_label
        from app.models_loader import network_ml_model
        from unittest.mock import MagicMock
        
        orig_loaded = network_ml_model.loaded
        orig_model = network_ml_model.model
        orig_inverse = network_ml_model.inverse_label_map
        
        try:
            mock_model = MagicMock(spec=[])  # No classes_ attribute
            network_ml_model.model = mock_model
            network_ml_model.loaded = True
            network_ml_model.inverse_label_map = {0: "Normal", 1: "Attack"}
            
            assert _safe_class_to_label(0) == "Normal"
            assert _safe_class_to_label(1) == "Attack"
        finally:
            network_ml_model.loaded = orig_loaded
            network_ml_model.model = orig_model
            network_ml_model.inverse_label_map = orig_inverse


class TestAnalyzeFlowDebugMode:
    """Tests for analyze_flow with debug mode enabled."""
    
    def test_analyze_flow_no_crash_with_string_classes_debug_on(self):
        """Test that analyze_flow doesn't crash when debug is ON and model.classes_ are strings."""
        import os
        
        # Enable debug mode
        os.environ["NETWORK_ML_DEBUG"] = "1"
        os.environ["NETWORK_ML_DEBUG_SAMPLE_RATE"] = "1"
        
        # Reload module to pick up env vars
        import importlib
        import app.detectors.network_ml_detector as detector
        importlib.reload(detector)
        
        from app.models_loader import network_ml_model
        from unittest.mock import MagicMock
        import numpy as np
        
        orig_loaded = network_ml_model.loaded
        orig_model = network_ml_model.model
        orig_feature_list = network_ml_model.feature_list
        orig_label_map = network_ml_model.label_map
        
        try:
            # Mock model with STRING classes (the bug scenario)
            mock_model = MagicMock()
            mock_model.predict_proba.return_value = np.array([[0.1, 0.8, 0.05, 0.05]])
            mock_model.classes_ = np.array(["Normal Traffic", "DDoS", "DoS", "Port Scanning"])
            network_ml_model.model = mock_model
            network_ml_model.loaded = True
            network_ml_model.feature_list = ["feat1", "feat2", "feat3"]
            network_ml_model.label_map = {
                "Normal Traffic": 0,
                "DDoS": 1,
                "DoS": 2,
                "Port Scanning": 3
            }
            
            flow_data = {
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": "TCP",
                "bidirectional_duration_ms": 1000,
                "bidirectional_packets": 100,
                "bidirectional_bytes": 10000,
            }
            
            # This should NOT crash even with string classes_ and debug ON
            # The old code would crash with int("DDoS")
            result = detector.analyze_flow(flow_data)
            
            # We expect a detection (DDoS with 0.8 prob)
            # May still be None due to feature mapping, but should NOT crash
            # The key test is: no exception raised
            
        finally:
            network_ml_model.loaded = orig_loaded
            network_ml_model.model = orig_model
            network_ml_model.feature_list = orig_feature_list
            network_ml_model.label_map = orig_label_map
            os.environ["NETWORK_ML_DEBUG"] = "0"


class TestGetNetworkMlHealth:
    """Tests for get_network_ml_health function."""
    
    def test_health_returns_expected_keys(self):
        """Test that health function returns all expected keys."""
        from app.detectors.network_ml_detector import get_network_ml_health
        
        health = get_network_ml_health()
        
        assert "loaded" in health
        assert "features_count" in health
        assert "labels_count" in health
        assert "benign_label" in health
        assert "allowed_labels" in health
        assert "thresholds" in health
        assert "filters" in health
        assert "counters" in health
        
        # Check nested structure
        assert "global" in health["thresholds"]
        assert "per_label" in health["thresholds"]
        
        assert "strict_filters" in health["filters"]
        assert "disable_gating" in health["filters"]
        assert "disable_allowlist" in health["filters"]
        
        assert "total_flows_seen" in health["counters"]
        assert "detections_created" in health["counters"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

