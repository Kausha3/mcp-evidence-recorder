from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "MCP Evidence Recorder"
    environment: str = Field(default="development")
    database_path: Path = Field(default=Path("data/audit.sqlite3"))
    target_mcp_url: str = Field(default="http://127.0.0.1:9000/mcp")
    policy_path: Path = Field(default=Path("config/policies.json"))
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    request_timeout_seconds: float = Field(default=30.0)
    max_body_bytes: int = Field(default=2_000_000)
    slack_webhook_url: Optional[str] = None
    admin_token: Optional[str] = None
    proxy_token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "Settings":
        import os

        target_mcp_url = os.getenv("TARGET_MCP_URL", "http://127.0.0.1:9000/mcp")
        if not target_mcp_url.startswith(("http://", "https://")):
            raise ValueError("TARGET_MCP_URL must start with http:// or https://")

        return cls(
            app_name=os.getenv("APP_NAME", "MCP Evidence Recorder"),
            environment=os.getenv("ENVIRONMENT", "development"),
            database_path=Path(os.getenv("DATABASE_PATH", "data/audit.sqlite3")),
            target_mcp_url=target_mcp_url.rstrip("/"),
            policy_path=Path(os.getenv("POLICY_PATH", "config/policies.json")),
            cors_origins=[
                origin.strip()
                for origin in os.getenv("CORS_ORIGINS", "*").split(",")
                if origin.strip()
            ],
            request_timeout_seconds=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
            max_body_bytes=int(os.getenv("MAX_BODY_BYTES", "2000000")),
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL") or None,
            admin_token=os.getenv("ADMIN_TOKEN") or None,
            proxy_token=os.getenv("PROXY_TOKEN") or None,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
