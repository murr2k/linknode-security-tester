"""Configuration management for Linknode Security Tester."""

import os
from typing import Optional, Dict, Any, List
from pathlib import Path
import yaml
from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings


class ZAPConfig(BaseModel):
    """OWASP ZAP configuration."""
    api_key: str = Field(default="changeme", description="ZAP API key")
    host: str = Field(default="localhost", description="ZAP daemon host")
    port: int = Field(default=8090, description="ZAP daemon port")
    proxy_host: str = Field(default="localhost", description="ZAP proxy host")
    proxy_port: int = Field(default=8090, description="ZAP proxy port")
    
    @property
    def base_url(self) -> str:
        """Get ZAP base URL."""
        return f"http://{self.host}:{self.port}"


class ScanningConfig(BaseModel):
    """Scanning configuration."""
    timeout: int = Field(default=300, description="Scan timeout in seconds")
    max_depth: int = Field(default=10, description="Maximum crawl depth")
    threads: int = Field(default=5, description="Number of scanning threads")
    user_agent: str = Field(
        default="Linknode Security Tester/1.0",
        description="User agent string"
    )
    exclude_urls: List[str] = Field(
        default_factory=list,
        description="URL patterns to exclude"
    )


class QualityConfig(BaseModel):
    """Quality assessment configuration."""
    lighthouse_enabled: bool = Field(
        default=True,
        description="Enable Lighthouse performance testing"
    )
    axe_enabled: bool = Field(
        default=True,
        description="Enable Axe accessibility testing"
    )
    seo_checks: bool = Field(
        default=True,
        description="Enable SEO analysis"
    )
    mobile_testing: bool = Field(
        default=True,
        description="Enable mobile responsiveness testing"
    )


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    include_screenshots: bool = Field(
        default=True,
        description="Include screenshots in reports"
    )
    risk_threshold: str = Field(
        default="medium",
        description="Minimum risk level to include in reports"
    )
    output_formats: List[str] = Field(
        default=["html", "json"],
        description="Report output formats"
    )
    template_dir: Path = Field(
        default=Path("templates"),
        description="Report template directory"
    )


class Settings(BaseSettings):
    """Main application settings."""
    
    # Application settings
    app_name: str = "Linknode Security Tester"
    version: str = "1.0.0"
    debug: bool = False
    
    # Component configurations
    zap: ZAPConfig = Field(default_factory=ZAPConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    quality: QualityConfig = Field(default_factory=QualityConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    
    # Database settings
    database_url: str = Field(
        default="sqlite:///./linknode_security.db",
        description="Database connection URL"
    )
    
    # API settings
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_reload: bool = Field(default=False, description="API auto-reload")
    
    class Config:
        env_prefix = "LST_"
        env_file = ".env"
        env_file_encoding = "utf-8"
    
    @classmethod
    def from_yaml(cls, config_path: Path) -> "Settings":
        """Load settings from YAML file."""
        if config_path.exists():
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
                return cls(**config_data)
        return cls()
    
    def to_yaml(self, config_path: Path) -> None:
        """Save settings to YAML file."""
        config_data = self.dict(exclude_unset=True)
        with open(config_path, "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)


# Global settings instance
settings = Settings()

# Load from config.yaml if it exists
config_file = Path("config.yaml")
if config_file.exists():
    settings = Settings.from_yaml(config_file)