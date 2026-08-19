"""Application Tier Configuration Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Enterprise Portal Application Settings."""

    app_name: str = "Enterprise Portal & Intentionally Vulnerable API"
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    database_url: str = Field(
        default="sqlite:///./data/app_portal.db", alias="APP_DB_URL"
    )
    secret_key: str = Field(
        default="lab-development-insecure-key-do-not-use-in-prod",
        alias="APP_SECRET_KEY",
    )
    siem_endpoint: str = Field(
        default="http://172.28.90.10:8088/api/v1/events",
        alias="SIEM_ENDPOINT",
    )
    enable_vulnerabilities: bool = Field(
        default=True,
        description="Toggle intentional vulnerabilities for detection testing.",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


app_settings = AppSettings()
