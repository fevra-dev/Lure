"""
lure/config.py
Centralised settings via pydantic-settings.
All configuration loaded from environment variables / .env file.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LureSettings(BaseSettings):
    """
    All Lure configuration. Values loaded from:
      1. Environment variables
      2. .env file (in working directory)
      3. Defaults defined here
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Threat Intel APIs ────────────────────────────────────────────────
    vt_api_key: Optional[str] = None
    abuseipdb_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    urlscan_key: Optional[str] = None
    otx_key: Optional[str] = None
    phishtank_key: Optional[str] = None
    gsb_key: Optional[str] = None

    # ── SOC Integrations ─────────────────────────────────────────────────
    thehive_url: Optional[str] = None
    thehive_key: Optional[str] = None
    misp_url: Optional[str] = None
    misp_key: Optional[str] = None

    # ── LLM ──────────────────────────────────────────────────────────────
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b"

    # ── Cache TTLs (hours) ───────────────────────────────────────────────
    cache_ttl_vt: int = 48
    cache_ttl_abuseipdb: int = 24
    cache_ttl_shodan: int = 72
    cache_ttl_urlscan: int = 24
    cache_ttl_otx: int = 24
    cache_ttl_urlhaus: int = 6
    cache_ttl_whois: int = 168
    cache_ttl_gsb: int = 1

    # ── Behaviour ────────────────────────────────────────────────────────
    log_level: str = "INFO"
    max_redirect_hops: int = 5
    urlscan_poll_timeout: int = 60   # seconds
    request_timeout: int = 30        # seconds for HTTP requests

    # ── Scoring thresholds ───────────────────────────────────────────────
    threshold_suspicious: float = 3.0
    threshold_likely_phishing: float = 5.0
    threshold_confirmed_malicious: float = 8.0

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()

    def api_keys_configured(self) -> dict[str, bool]:
        """Returns which API keys are configured."""
        return {
            "virustotal": bool(self.vt_api_key),
            "abuseipdb": bool(self.abuseipdb_key),
            "shodan": bool(self.shodan_api_key),
            "urlscan": bool(self.urlscan_key),
            "otx": bool(self.otx_key),
            "phishtank": bool(self.phishtank_key),
            "google_safe_browsing": bool(self.gsb_key),
            "thehive": bool(self.thehive_url and self.thehive_key),
            "misp": bool(self.misp_url and self.misp_key),
        }

    def missing_keys(self) -> list[str]:
        return [k for k, v in self.api_keys_configured().items() if not v]


@lru_cache(maxsize=1)
def get_settings() -> LureSettings:
    """Returns a cached singleton settings instance."""
    return LureSettings()
