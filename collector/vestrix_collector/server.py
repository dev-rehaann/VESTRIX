"""Minimal asyncio-accepting, mutually authenticated TLS ingest server."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import socket
import ssl
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from . import forensics
from .config import CollectorConfig
from .models import CSIEvent, PayloadValidationError, validate_payload

EventLogger = Callable[[CSIEvent], None]


class AllowlistError(ValueError):
    """Raised when the node enrollment allow-list is invalid."""


class PayloadReadError(ValueError):
    """Raised when the newline-delimited wire frame is invalid."""


def load_enrolled_nodes(path: Path) -> frozenset[str]:
    """Load exact certificate-CN node IDs from a YAML allow-list."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AllowlistError(f"could not load node allow-list {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"nodes"}:
        raise AllowlistError("node allow-list must contain exactly one 'nodes' key")
    nodes = raw["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise AllowlistError("node allow-list 'nodes' must be a non-empty list")
    if not all(isinstance(node, str) and node for node in nodes):
        raise AllowlistError("every enrolled node ID must be a non-empty string")
    if len(nodes) != len(set(nodes)):
        raise AllowlistError("node allow-list contains duplicate node IDs")
    return frozenset(nodes)


def build_server_tls_context(config: CollectorConfig) -> ssl.SSLContext:
    """Build a server context requiring a non-revoked project-CA certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(config.tls.ca_cert))
    context.load_verify_locations(cafile=str(config.tls.crl_path))
    context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    context.load_cert_chain(
        certfile=str(config.tls.server_cert), keyfile=str(config.tls.server_key)
    )
    return context


class CollectorServer:
    """One-payload-per-connection mTLS CSI ingest server."""

    def __init__(
        self,
        config: CollectorConfig,
        *,
        event_logger: EventLogger | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._config = config
        self._event_logger = event_logger or forensics.log_event
        self._logger = logger or logging.getLogger("vestrix_collector.decisions")
        self._security_state_lock = threading.Lock()
        self._enrolled_nodes, self._tls_context = self._load_security_state()
        self._sequence_lock = threading.Lock()
        self._last_sequences: dict[str, int] = {}
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task[None] | None = None
        self._connection_tasks: set[asyncio.Task[None]] = set()

    @property
    def port(self) -> int:
        """Return the bound port after startup."""
        if self._listener is None:
            raise RuntimeError("collector has not been started")
        return int(self._listener.getsockname()[1])

    async def reload_security_state(self) -> None:
        """Reload the allow-list and CRL-backed TLS context for new connections."""
        enrolled_nodes, tls_context = await asyncio.to_thread(
            self._load_security_state
        )
        with self._security_state_lock:
            self._enrolled_nodes = enrolled_nodes
            self._tls_context = tls_context
        self._logger.info(
            "collector security state reloaded",
            extra={
                "event": "collector_lifecycle",
                "decision_fields": {
                    "state": "security_state_reloaded",
                    "enrolled_node_count": len(enrolled_nodes),
                },
            },
        )

    def _load_security_state(self) -> tuple[frozenset[str], ssl.SSLContext]:
        return (
            load_enrolled_nodes(self._config.allowlist_path),
            build_server_tls_context(self._config),
        )

    async def start(self) -> None:
        """Bind the listener and start accepting sockets."""
        if self._listener is not None:
            raise RuntimeError("collector is already running")
        family = socket.AF_INET6 if ":" in self._config.server.host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setblocking(False)
        listener.bind((self._config.server.host, self._config.server.port))
        listener.listen(socket.SOMAXCONN)
        self._listener = listener
        self._accept_task = asyncio.create_task(self._accept_loop())
        self._logger.info(
            "collector listening",
            extra={
                "event": "collector_lifecycle",
                "decision_fields": {
                    "host": self._config.server.host,
                    "port": self.port,
                    "state": "started",
                },
            },
        )

    async def close(self) -> None:
        """Stop accepting new connections and wait for active handlers."""
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        if self._accept_task is not None:
            self._accept_task.cancel()
            await asyncio.gather(self._accept_task, return_exceptions=True)
            self._accept_task = None
        if self._connection_tasks:
            await asyncio.gather(*tuple(self._connection_tasks), return_exceptions=True)
        self._logger.info(
            "collector stopped",
            extra={
                "event": "collector_lifecycle",
                "decision_fields": {"state": "stopped"},
            },
        )

    async def _accept_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._listener is not None:
            try:
                client, address = await loop.sock_accept(self._listener)
            except asyncio.CancelledError:
                return
            except OSError:
                if self._listener is None:
                    return
                raise
            task = asyncio.create_task(
                asyncio.to_thread(self._handle_socket, client, address)
            )
            self._connection_tasks.add(task)
            task.add_done_callback(self._connection_tasks.discard)

    def _handle_socket(self, client: socket.socket, address: Any) -> None:
        peer = _format_peer(address)
        try:
            client.setblocking(True)
            client.settimeout(self._config.server.handshake_timeout_seconds)
            with self._security_state_lock:
                tls_context = self._tls_context
                enrolled_nodes = self._enrolled_nodes
            with tls_context.wrap_socket(client, server_side=True) as tls_socket:
                self._handle_tls_socket(tls_socket, peer, enrolled_nodes)
        except (ssl.SSLError, TimeoutError, OSError) as exc:
            self._decision(
                "reject",
                "tls_handshake_failed",
                peer=peer,
                error_type=type(exc).__name__,
            )
            client.close()
        except Exception as exc:
            # An unexpected handler failure is still a security decision. Keep the
            # exception content out of logs, but never fail silently.
            self._decision(
                "reject",
                "internal_server_error",
                peer=peer,
                error_type=type(exc).__name__,
            )
            client.close()

    def _handle_tls_socket(
        self,
        tls_socket: ssl.SSLSocket,
        peer: str,
        enrolled_nodes: frozenset[str],
    ) -> None:
        certificate = tls_socket.getpeercert()
        common_names = _certificate_common_names(certificate)
        if len(common_names) != 1:
            self._reject_tls_socket(tls_socket, "invalid_certificate_cn", peer=peer)
            return
        certificate_node_id = common_names[0]
        if certificate_node_id not in enrolled_nodes:
            self._reject_tls_socket(
                tls_socket,
                "unenrolled_certificate_cn",
                peer=peer,
                certificate_node_id=certificate_node_id,
            )
            return

        tls_socket.settimeout(self._config.server.read_timeout_seconds)
        try:
            raw_payload = _read_json_line(
                tls_socket, self._config.server.max_payload_bytes
            )
            decoded = json.loads(raw_payload)
            event = validate_payload(decoded)
        except TimeoutError:
            self._reject_tls_socket(
                tls_socket,
                "payload_read_timeout",
                peer=peer,
                certificate_node_id=certificate_node_id,
            )
            return
        except (PayloadReadError, PayloadValidationError) as exc:
            self._reject_tls_socket(
                tls_socket,
                str(exc),
                peer=peer,
                certificate_node_id=certificate_node_id,
            )
            return
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            self._reject_tls_socket(
                tls_socket,
                "invalid_json_payload",
                peer=peer,
                certificate_node_id=certificate_node_id,
            )
            return

        if not hmac.compare_digest(event["node_id"], certificate_node_id):
            self._reject_tls_socket(
                tls_socket,
                "node_id_certificate_cn_mismatch",
                peer=peer,
                certificate_node_id=certificate_node_id,
                payload_node_id=event["node_id"],
                sequence_number=event["sequence_number"],
            )
            return

        with self._sequence_lock:
            previous = self._last_sequences.get(certificate_node_id)
            is_replay = previous is not None and event["sequence_number"] <= previous
            if not is_replay:
                # Reserve before handoff. A failed handoff consumes the sequence
                # rather than reopening a replay window for the same event.
                self._last_sequences[certificate_node_id] = event["sequence_number"]
        if is_replay:
            self._reject_tls_socket(
                tls_socket,
                "replayed_or_out_of_order_sequence",
                peer=peer,
                node_id=certificate_node_id,
                sequence_number=event["sequence_number"],
                last_sequence_number=previous,
            )
            return

        try:
            self._event_logger(event)
        except Exception as exc:
            self._reject_tls_socket(
                tls_socket,
                "forensics_handoff_failed",
                peer=peer,
                node_id=certificate_node_id,
                sequence_number=event["sequence_number"],
                error_type=type(exc).__name__,
            )
            return

        self._decision(
            "accept",
            "authenticated_event_handed_off",
            peer=peer,
            node_id=certificate_node_id,
            sequence_number=event["sequence_number"],
            csi_window_sha256=event["csi_window_sha256"],
        )
        _send_response(tls_socket, "accepted", "authenticated_event_handed_off")

    def _reject_tls_socket(
        self, tls_socket: ssl.SSLSocket, reason: str, **fields: Any
    ) -> None:
        self._decision("reject", reason, **fields)
        _send_response(tls_socket, "rejected", reason)

    def _decision(self, decision: str, reason: str, **fields: Any) -> None:
        self._logger.info(
            f"ingest {decision}",
            extra={
                "event": "ingest_decision",
                "decision_fields": {
                    "decision": decision,
                    "reason": reason,
                    **fields,
                },
            },
        )


def _certificate_common_names(certificate: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for relative_distinguished_name in certificate.get("subject", ()):
        for key, value in relative_distinguished_name:
            if key == "commonName" and isinstance(value, str):
                names.append(value)
    return names


def _read_json_line(tls_socket: ssl.SSLSocket, limit: int) -> str:
    payload = bytearray()
    while len(payload) <= limit:
        chunk = tls_socket.recv(min(4096, limit + 1 - len(payload)))
        if not chunk:
            raise PayloadReadError("payload_missing_newline")
        newline_index = chunk.find(b"\n")
        if newline_index >= 0:
            payload.extend(chunk[:newline_index])
            break
        payload.extend(chunk)
    if len(payload) > limit:
        raise PayloadReadError("payload_too_large")
    if not payload:
        raise PayloadReadError("empty_payload")
    return payload.decode("utf-8")


def _send_response(tls_socket: ssl.SSLSocket, status: str, reason: str) -> None:
    response = json.dumps(
        {"status": status, "reason": reason}, separators=(",", ":")
    ).encode("utf-8")
    try:
        tls_socket.sendall(response + b"\n")
    except OSError:
        # The accept/reject decision is already logged; a peer may disconnect before
        # reading its response and must not erase that audit record.
        return


def _format_peer(address: Any) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return str(address)
