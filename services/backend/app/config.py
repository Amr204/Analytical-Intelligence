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

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # pydantic-settings v2 style (still reads .env)
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://ai:ai2025@postgres:5432/ai_db"

    # Security
    ingest_api_key: str = "ONuMcisin3paJYkPDaf0tt9n2deEBeaN"
    ui_session_secret: str = "CHANGE_ME_IN_PRODUCTION_32CHARS!"  # For SessionMiddleware

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000

    # Model paths (env can override: SSH_MODEL_PATH, NETWORK_MODEL_PATH, ...)
    ssh_model_path: str = DEFAULT_SSH_MODEL_PATH

    # Detection thresholds
    # network_ml_threshold: float = 0.60 # REMOVED

    # SSH Detection
    ssh_bruteforce_window_seconds: int = 300
    ssh_bruteforce_threshold: int = 5
    ssh_spray_username_threshold: int = 10 
    ssh_ml_threshold: float = 0.80  # Increased for higher confidence (was 0.5) 

    # Network ML
    # REMOVED: Network RF model is no longer used.
    
    # Telegram Alerts (Optional)
    telegram_enabled: bool = True
    telegram_bot_token: str = ""  # MUST be set via env, never hardcoded
    telegram_chat_id: str = "-5228638760"  # Default: Analytical Intelligence | SOC Team
    telegram_min_severity: str = "HIGH"  # Only send alerts >= this severity
    telegram_rate_limit_per_min: int = 20
    telegram_dedup_window_seconds: int = 60
    telegram_suricata_dedup_window_seconds: int = 300  # 5 min for suricata DDoS bursts
    telegram_timeout_seconds: int = 10
    telegram_parse_mode: str = "HTML"
    telegram_disable_web_preview: bool = True
    telegram_startup_test: bool = False  # Send test message on startup
    public_dashboard_base_url: str = ""  # Optional: for dashboard links in alerts
    
    # Suricata Alert Handling
    suricata_rollup_window_minutes: int = 5  # Time bucket for incident grouping (env: SURICATA_ROLLUP_WINDOW_MINUTES)
    suricata_local_sid_min: int = 1000000  # Minimum SID for local AI rules
    suricata_local_sid_max: int = 1009999  # Maximum SID for local AI rules
    
    # Timezone for UI display (DB always stores UTC)
    # Valid timezone names: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
    # Valid timezone names: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
    app_timezone: str = "Asia/Kuwait"  # Local timezone for UI display (env: APP_TIMEZONE)
    
    # Social Links (for Home page, optional)
    app_telegram_url: str = "https://t.me/+ni5ZN6NtgrkzMjg8"  # Telegram channel/group URL
    app_github_url: str = "https://github.com/Amr204/Analytical-Intelligence"  # GitHub repo URL
    app_discord_url: str = "https://discord.gg/Be567jTM"  # Discord server URL
    app_drive_url: str = "https://drive.google.com/drive/u/2/my-drive"  # Google Drive URL




# Global settings instance
settings = Settings()
