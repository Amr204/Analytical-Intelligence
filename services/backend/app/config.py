"""
Analytical-Intelligence v1 - Configuration
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Set
from pydantic_settings import BaseSettings, SettingsConfigDict


def _detect_project_root(start: Path) -> Path:
    """
    Detect the nearest parent directory that contains 'models/'.
    - In dev repo: .../Analytical-Intelligence/models
    - In Docker:   /app/models (mounted)
    """
    start = start.resolve()
    for p in [start] + list(start.parents):
        if (p / "models").exists():
            return p
    # Fallback: backend directory (won't crash, but paths may not exist)
    return start.parents[1]


PROJECT_ROOT = _detect_project_root(Path(__file__).resolve())

# SSH model path
DEFAULT_SSH_MODEL_PATH = str(PROJECT_ROOT / "models/ssh/ssh_lstm.joblib")

# RF Network model paths 
DEFAULT_NETWORK_MODEL_PATH = str(PROJECT_ROOT / "models/RF/random_forest.joblib")
DEFAULT_NETWORK_FEATURES_PATH = str(PROJECT_ROOT / "models/RF/feature_list.json")
DEFAULT_NETWORK_LABELS_PATH = str(PROJECT_ROOT / "models/RF/label_map.json")
DEFAULT_NETWORK_PREPROCESS_PATH = str(PROJECT_ROOT / "models/RF/preprocess_config.json")
DEFAULT_NETWORK_METRICS_PATH = str(PROJECT_ROOT / "models/RF/metrics.json")

# Default allowlist: only these attack labels will create detections
DEFAULT_NETWORK_LABEL_ALLOWLIST = "DoS,DDoS,Port Scanning,Brute Force"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # pydantic-settings v2 style (still reads .env)
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    # Database
    database_url: str = "postgresql+asyncpg://ai:ai2025@postgres:5432/ai_db"

    # Security
    ingest_api_key: str = "ONuMcisin3paJYkPDaf0tt9n2deEBeaN"

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000

    # Model paths (env can override: SSH_MODEL_PATH, NETWORK_MODEL_PATH, ...)
    ssh_model_path: str = DEFAULT_SSH_MODEL_PATH
    network_model_path: str = DEFAULT_NETWORK_MODEL_PATH
    network_features_path: str = DEFAULT_NETWORK_FEATURES_PATH
    network_labels_path: str = DEFAULT_NETWORK_LABELS_PATH
    network_preprocess_path: str = DEFAULT_NETWORK_PREPROCESS_PATH
    network_metrics_path: str = DEFAULT_NETWORK_METRICS_PATH

    # Detection thresholds
    network_ml_threshold: float = 0.60

    # SSH Detection
    ssh_bruteforce_window_seconds: int = 300
    ssh_bruteforce_threshold: int = 5
    ssh_spray_username_threshold: int = 10 

    # Network ML
    ml_dedup_window_seconds: int = 300
    ml_min_flow_rate_pps: int = 100
    ml_min_bytes_per_second: int = 1000
    ml_cooldown_seconds_per_src: int = 3600

    # Network Label Allowlist (comma-separated)
    # Only these labels will create detection records
    # Default: DoS, DDoS, Port Scanning, Brute Force
    network_label_allowlist: str = DEFAULT_NETWORK_LABEL_ALLOWLIST
    
    # What to do with non-allowed labels: "ignore" (skip) or "map_to_normal" (log only)
    # Recommended: "ignore" - don't store any record for Web Attacks, Bots, etc.
    network_non_allow_action: str = "ignore"

    @property
    def network_label_allowlist_set(self) -> Set[str]:
        """Parse allowlist string into a set of normalized labels."""
        if not self.network_label_allowlist:
            return set()
        return {label.strip() for label in self.network_label_allowlist.split(",") if label.strip()}


# Global settings instance
settings = Settings()
