"""
Analytical-Intelligence v1 - Configuration
"""

import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Database
    database_url: str = "postgresql+asyncpg://ai:ai2025@postgres:5432/ai_db"
    
    # Security
    ingest_api_key: str = "ONuMcisin3paJYkPDaf0tt9n2deEBeaN"
    
    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    
    # Model paths
    ssh_model_path: str = "/app/models/ssh/ssh_lstm.joblib"
    network_model_path: str = "/app/models/network/model.joblib"
    network_features_path: str = "/app/models/network/feature_list.json"
    network_labels_path: str = "/app/models/network/label_map.json"
    network_preprocess_path: str = "/app/models/network/preprocess_config.json"
    
    # Detection thresholds
    network_ml_threshold: float = 0.60
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
