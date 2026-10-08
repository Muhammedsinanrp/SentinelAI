"""
CYBERSHIELD X - Global Configuration
Supports YAML files and environment variable overrides.
"""
import os
import yaml
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = BASE_DIR / "scope.yaml"
DATA_DIR = BASE_DIR / "cybershield" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "cybershield.db"

class RateLimitConfig(BaseModel):
    requests_per_second: float = 2.0
    burst: int = 5

class AIConfig(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    max_tokens: int = 1500
    base_url: str = Field(default_factory=lambda: os.getenv("AI_BASE_URL", "https://api.openai.com/v1"))
    api_key: str = Field(default_factory=lambda: os.getenv("AI_API_KEY", ""))

class Settings(BaseModel):
    app_name: str = "CYBERSHIELD X"
    version: str = "2.0.0"
    environment: str = "production"
    program: str = "Enterprise Security Operations"
    in_scope: List[str] = [
        "httpbin.org",
        "*.httpbin.org",
        "example.com",
        "*.example.com"
    ]
    out_of_scope: List[str] = [
        "status.example.com",
        "payment.example.com"
    ]
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    proxy_url: Optional[str] = Field(default_factory=lambda: os.getenv("PROXY_URL"))
    db_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH.as_posix()}"))

def load_settings(path: Optional[Path] = None) -> Settings:
    target_path = path or CONFIG_PATH
    data = {}
    if target_path.exists():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except Exception as e:
            print(f"[!] Warning: failed to parse {target_path}: {e}")

    settings = Settings(**data)
    if os.getenv("AI_API_KEY"):
        settings.ai.api_key = os.getenv("AI_API_KEY")
    if os.getenv("AI_BASE_URL"):
        settings.ai.base_url = os.getenv("AI_BASE_URL")
    if os.getenv("AI_MODEL"):
        settings.ai.model = os.getenv("AI_MODEL")
    return settings

settings = load_settings()
