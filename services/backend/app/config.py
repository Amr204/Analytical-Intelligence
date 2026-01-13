"""
Analytical-Intelligence v1 - Configuration
"""

from __future__ import annotations

from pathlib import Path
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

DEFAULT_SSH_MODEL_PATH = str(PROJECT_ROOT / "models/ssh/ssh_lstm.joblib")
DEFAULT_NETWORK_MODEL_PATH = str(PROJECT_ROOT / "models/network/model.joblib")
DEFAULT_NETWORK_FEATURES_PATH = str(PROJECT_ROOT / "models/network/feature_list.json")
DEFAULT_NETWORK_LABELS_PATH = str(PROJECT_ROOT / "models/network/label_map.json")
DEFAULT_NETWORK_PREPROCESS_PATH = str(PROJECT_ROOT / "models/network/preprocess_config.json")


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

    # Detection thresholds
    network_ml_threshold: float = 0.60


# Global settings instance
settings = Settings()
