"""YAML configuration loading for the collector."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when collector configuration is absent or invalid."""


@dataclass(frozen=True, slots=True)
class TLSConfig:
    ca_cert: Path
    crl_path: Path
    server_cert: Path
    server_key: Path


@dataclass(frozen=True, slots=True)
class ServerConfig:
    host: str
    port: int
    handshake_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 10.0
    max_payload_bytes: int = 65_536


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    tls: TLSConfig
    allowlist_path: Path
    server: ServerConfig


def _mapping(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigError(f"{name} must be a YAML mapping")
    return value


def _exact_keys(data: dict[str, Any], expected: set[str], name: str) -> None:
    unknown = set(data) - expected
    missing = expected - set(data)
    if unknown:
        raise ConfigError(f"{name} has unknown keys: {', '.join(sorted(unknown))}")
    if missing:
        raise ConfigError(f"{name} is missing keys: {', '.join(sorted(missing))}")


def _resolve_path(base_dir: Path, value: object, name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} must be a non-empty path string")
    path = Path(value)
    return path if path.is_absolute() else (base_dir / path).resolve()


def _positive_float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"{name} must be a positive number")
    return float(value)


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def load_config(path: str | Path) -> CollectorConfig:
    """Load a collector config, resolving file paths relative to the YAML file."""
    config_path = Path(path).resolve()
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not load config {config_path}: {exc}") from exc

    root = _mapping(raw, "config")
    _exact_keys(root, {"tls", "allowlist_path", "server"}, "config")
    tls = _mapping(root["tls"], "tls")
    _exact_keys(tls, {"ca_cert", "crl_path", "server_cert", "server_key"}, "tls")
    server = _mapping(root["server"], "server")
    required_server_keys = {"host", "port"}
    optional_server_keys = {
        "handshake_timeout_seconds",
        "read_timeout_seconds",
        "max_payload_bytes",
    }
    unknown_server_keys = set(server) - required_server_keys - optional_server_keys
    missing_server_keys = required_server_keys - set(server)
    if unknown_server_keys:
        raise ConfigError(
            f"server has unknown keys: {', '.join(sorted(unknown_server_keys))}"
        )
    if missing_server_keys:
        raise ConfigError(
            f"server is missing keys: {', '.join(sorted(missing_server_keys))}"
        )

    host = server["host"]
    port = server["port"]
    if not isinstance(host, str) or not host.strip():
        raise ConfigError("server.host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ConfigError("server.port must be an integer from 1 through 65535")

    base_dir = config_path.parent
    return CollectorConfig(
        tls=TLSConfig(
            ca_cert=_resolve_path(base_dir, tls["ca_cert"], "tls.ca_cert"),
            crl_path=_resolve_path(base_dir, tls["crl_path"], "tls.crl_path"),
            server_cert=_resolve_path(base_dir, tls["server_cert"], "tls.server_cert"),
            server_key=_resolve_path(base_dir, tls["server_key"], "tls.server_key"),
        ),
        allowlist_path=_resolve_path(
            base_dir, root["allowlist_path"], "allowlist_path"
        ),
        server=ServerConfig(
            host=host,
            port=port,
            handshake_timeout_seconds=_positive_float(
                server.get("handshake_timeout_seconds", 10.0),
                "server.handshake_timeout_seconds",
            ),
            read_timeout_seconds=_positive_float(
                server.get("read_timeout_seconds", 10.0),
                "server.read_timeout_seconds",
            ),
            max_payload_bytes=_positive_int(
                server.get("max_payload_bytes", 65_536),
                "server.max_payload_bytes",
            ),
        ),
    )
