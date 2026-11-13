"""
Configuration Management Module
Loads configuration from environment variables / .env (12-factor app style).
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings, read from the environment or a local .env file"""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    # App
    app_name: str = "Cloud SIEM & GRC Platform"
    app_version: str = "1.0.0"
    environment: str = Field(default="development", alias="ENV")
    debug: bool = Field(default=False, alias="DEBUG")
    log_level: str = "INFO"

    # Persistence
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'data' / 'platform.db').as_posix()}"

    # AWS
    aws_enabled: bool = True
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_guardduty_detector_id: Optional[str] = None

    # Azure
    azure_enabled: bool = True
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_subscription_id: Optional[str] = None

    # Threat intelligence
    vt_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None

    # API
    api_key: Optional[str] = None
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    rate_limit_rpm: int = 100
    max_body_bytes: int = 2_000_000

    @property
    def aws_configured(self) -> bool:
        return bool(self.aws_access_key_id and self.aws_secret_access_key)

    @property
    def azure_configured(self) -> bool:
        return bool(
            self.azure_tenant_id
            and self.azure_client_id
            and self.azure_client_secret
            and self.azure_subscription_id
        )

    @property
    def threat_intel_configured(self) -> bool:
        return bool(self.vt_api_key or self.shodan_api_key or self.abuseipdb_api_key)


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings instance (safe to import; reads no files until called)"""
    return Settings()
