"""
PatchForge AI - Centralized Application Configuration
=====================================================
Loads strongly-typed configuration settings from environment variables and .env file
using Pydantic Settings.
"""

from functools import lru_cache
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Application Core ---
    PROJECT_NAME: str = "PatchForge AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "dev_patchforge_insecure_secret_key_change_in_production"
    JWT_SECRET: str = "dev_patchforge_jwt_secret_key_change_in_production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # --- Admin Bootstrap ---
    # Comma-separated emails that get ADMIN on first registration/login instead
    # of the default DEVELOPER role. This is the only way to reach an elevated
    # role - there is no in-app promotion endpoint, and self-registration always
    # ignores any client-supplied role. Set this to your own email before
    # deploying so you aren't permanently locked out of SECURITY_ENGINEER/ADMIN-only
    # actions (PR creation, repository deletion).
    ADMIN_EMAILS: str = ""

    # --- PostgreSQL Database ---
    POSTGRES_USER: str = "patchforge"
    POSTGRES_PASSWORD: str = "patchforge_secure_pass"
    POSTGRES_DB: str = "patchforge_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = "postgresql://patchforge:patchforge_secure_pass@localhost:5432/patchforge_db"

    # --- Redis Message Broker ---
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Local LLM Engine (Ollama) - kept for anyone running a local model ---
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:1.5b"
    OLLAMA_TIMEOUT_SECONDS: int = 120

    # --- Groq Cloud LLM Engine (default patch-generation backend) ---
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-20b"
    GROQ_TIMEOUT_SECONDS: int = 60

    # --- Sandbox Security ---
    DOCKER_SOCKET: str = "/var/run/docker.sock"
    SANDBOX_TIMEOUT_SECONDS: int = 30
    SANDBOX_MEMORY_LIMIT: str = "512m"
    SANDBOX_CPU_QUOTA: float = 1.0
    SANDBOX_NETWORK_DISABLED: bool = True

    # --- GitHub Integration & Webhooks ---
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_APP_PRIVATE_KEY_PATH: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: str = "patchforge_webhook_secret_hmac_256"
    GITHUB_ACCESS_TOKEN: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def allowed_hosts_list(self) -> List[str]:
        return [host.strip() for host in self.ALLOWED_HOSTS.split(",") if host.strip()]

    @property
    def admin_emails_list(self) -> List[str]:
        return [email.strip().lower() for email in self.ADMIN_EMAILS.split(",") if email.strip()]


@lru_cache()
def get_settings() -> Settings:
    """Returns cached application settings instance."""
    return Settings()
