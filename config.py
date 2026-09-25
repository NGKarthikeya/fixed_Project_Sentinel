"""
SwarmSentinel - Centralized Configuration
=========================================

Single source of truth for all configurable parameters.
Values are loaded from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

_PLACEHOLDER_SECRET_VALUES = {
    "YOUR_API_KEY_HERE",
    "YOUR_GOOGLE_AI_STUDIO_KEY_HERE",
}


class ConfigError(RuntimeError):
    """Raised when required runtime configuration is missing or unsafe."""



def _is_placeholder_secret(value: Optional[str]) -> bool:
    if not value:
        return False
    normalized = value.strip()
    if normalized in _PLACEHOLDER_SECRET_VALUES:
        return True
    return "YOUR_UPSTASH_PASSWORD" in normalized or "YOUR_UPSTASH_HOST" in normalized


@dataclass
class GraphConfig:
    """Pheromone graph tuning parameters."""
    decay_rate: float = 0.95
    min_threshold: float = 0.01
    decay_interval: float = 30.0
    max_nodes: int = 50000
    max_edges: int = 200000
    reinforcement_blend_old: float = 0.7
    reinforcement_blend_new: float = 0.3
    hotspot_threshold: float = 0.5
    backend: str = "memory"  # "memory" or "redis"


@dataclass
class DetectorConfig:
    """Anomaly detector thresholds."""
    zscore_threshold: float = 2.0
    zscore_max_delta: float = 50.0
    frequency_threshold: int = 2
    frequency_max_delta: float = 30.0
    sequence_unique_threshold: int = 3
    sequence_max_delta: float = 40.0
    min_history_samples: int = 3


@dataclass
class SwarmConfig:
    """Ant swarm agent parameters."""
    num_scouts: int = 5
    soldier_threshold: float = 15.0
    scout_pheromone_strength: float = 0.3
    soldier_pheromone_strength: float = 50.0
    queen_hotspot_min_strength: float = 3.0
    convergence_threshold: float = 5.0
    max_soldiers: int = 20
    investigation_timeout_seconds: float = 300.0


@dataclass
class CorrelationConfig:
    """Incident correlation parameters."""
    window_seconds: float = 300.0
    create_threshold: float = 60.0
    severity_critical: float = 80.0
    severity_high: float = 60.0
    severity_medium: float = 40.0


@dataclass
class QueueConfig:
    """Event queue parameters."""
    max_size: int = 10000
    batch_size: int = 50
    flush_interval: float = 0.5


@dataclass
class APIConfig:
    """API server configuration."""
    api_key: str = ""
    google_ai_studio_key: str = ""
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    cors_origins: list = field(default_factory=lambda: ["*"])
    trusted_proxy_ips: list = field(default_factory=list)
    ws_heartbeat_seconds: float = 30.0
    max_incidents_per_page: int = 50


@dataclass
class AppConfig:
    """Top-level application configuration."""
    graph: GraphConfig = field(default_factory=GraphConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    swarm: SwarmConfig = field(default_factory=SwarmConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    queue: QueueConfig = field(default_factory=QueueConfig)
    api: APIConfig = field(default_factory=APIConfig)
    version: str = "2.0.0"
    environment: str = "development"
    log_level: str = "INFO"
    redis_url: Optional[str] = None
    dataset_seed_on_startup: bool = True

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Load configuration from environment variables."""
        cfg = cls()

        def safe_int(name: str, default: int) -> int:
            try:
                value = os.getenv(name)
                return int(value.strip()) if value else default
            except (AttributeError, ValueError):
                return default

        def safe_float(name: str, default: float) -> float:
            try:
                value = os.getenv(name)
                return float(value.strip()) if value else default
            except (AttributeError, ValueError):
                return default

        # API
        cfg.api.api_key = (os.getenv("API_KEY") or "").strip()
        cfg.api.google_ai_studio_key = (os.getenv("GOOGLE_AI_STUDIO_KEY") or "").strip()
        cfg.api.rate_limit_requests = max(1, safe_int("RATE_LIMIT_REQUESTS", 30))
        cfg.api.rate_limit_window_seconds = max(1, safe_int("RATE_LIMIT_WINDOW_SECONDS", 60))
        cfg.api.cors_origins = [
            origin.strip()
            for origin in os.getenv(
                "CORS_ORIGINS",
                "http://localhost:8000,http://127.0.0.1:8000,https://mail.google.com,https://www.gmail.com",
            ).split(",")
            if origin.strip()
        ]
        cfg.api.trusted_proxy_ips = [
            address.strip()
            for address in os.getenv("TRUSTED_PROXY_IPS", "").split(",")
            if address.strip()
        ]

        # Graph
        cfg.graph.decay_rate = min(1.0, max(0.01, safe_float("GRAPH_DECAY_RATE", 0.95)))
        cfg.graph.backend = os.getenv("GRAPH_BACKEND", "memory")

        # Environment
        cfg.environment = os.getenv("ENVIRONMENT", "development")
        cfg.log_level = os.getenv("LOG_LEVEL", "INFO")
        cfg.redis_url = os.getenv("REDIS_URL")

        # Correlation
        cfg.correlation.window_seconds = max(10.0, safe_float("CORRELATION_WINDOW", 300.0))
        cfg.correlation.create_threshold = min(100.0, max(1.0, safe_float("CORRELATION_THRESHOLD", 60.0)))

        # Dataset seeding
        _seed_flag = os.getenv("DATASET_SEED_ON_STARTUP", "true").strip().lower()
        cfg.dataset_seed_on_startup = _seed_flag not in ("false", "0", "no")

        return cfg

    def validate_runtime_requirements(self) -> "AppConfig":
        """Fail fast when required or placeholder secrets are present."""
        if not self.api.api_key:
            raise ConfigError("API_KEY environment variable is required.")
        if _is_placeholder_secret(self.api.api_key):
            raise ConfigError("API_KEY must be replaced with a real secret before startup.")
        if self.api.google_ai_studio_key and _is_placeholder_secret(self.api.google_ai_studio_key):
            raise ConfigError("GOOGLE_AI_STUDIO_KEY contains a placeholder value.")
        if self.redis_url and _is_placeholder_secret(self.redis_url):
            raise ConfigError("REDIS_URL contains placeholder credentials.")
        if (
            self.environment == "production"
            and self.redis_url
            and "@" not in self.redis_url
            and os.getenv("REDIS_ALLOW_NO_AUTH", "").lower() != "true"
        ):
            raise ConfigError("REDIS_URL has no credentials and ENVIRONMENT=production. Set a password or explicitly allow this via REDIS_ALLOW_NO_AUTH=true.")
        if self.environment == "production" and (os.getenv("REQUIRE_REDIS_IN_PRODUCTION", "").lower() == "true" or self.graph.backend == "redis"):
            import storage
            if not storage._redis_available():
                raise ConfigError("Production environment requires a connected Redis instance.")
        return self

    def to_dict(self) -> dict:
        """Serialize config for /health or /metrics endpoints (redacts secrets)."""
        return {
            "version": self.version,
            "environment": self.environment,
            "graph_backend": self.graph.backend,
            "graph_max_nodes": self.graph.max_nodes,
            "queue_max_size": self.queue.max_size,
            "rate_limit": f"{self.api.rate_limit_requests}/{self.api.rate_limit_window_seconds}s",
            "api_key_set": bool(self.api.api_key),
            "google_ai_studio_key_set": bool(self.api.google_ai_studio_key),
            "redis_configured": bool(self.redis_url),
            "dataset_seed_on_startup": self.dataset_seed_on_startup,
        }


# Module-level singleton
config = AppConfig.from_env()
