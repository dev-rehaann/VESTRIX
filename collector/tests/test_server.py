from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import CertificateBundle, Identity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from forensics import verify_chain
from forensics.keys import generate_signing_key, save_private_key

from vestrix_collector.config import CollectorConfig, ServerConfig, TLSConfig
from vestrix_collector.models import CSIEvent
from vestrix_collector.server import CollectorServer


def _payload(sequence_number: int = 1) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "node_id": "node-01",
        "timestamp_utc": "2026-07-12T17:30:00.123Z",
        "csi_window_sha256": "a" * 64,
        "sequence_number": sequence_number,
    }


def _send_event(
    port: int,
    ca_cert: Path,
    identity: Identity,
    payload: dict[str, object] | None,
) -> dict[str, str]:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    context.check_hostname = False
    context.load_cert_chain(str(identity.cert), str(identity.key))
    with (
        socket.create_connection(("127.0.0.1", port), timeout=2) as raw_socket,
        context.wrap_socket(raw_socket, server_hostname="collector-test") as tls_socket,
    ):
        if payload is not None:
            tls_socket.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        response = tls_socket.makefile("rb").readline()
    decoded = json.loads(response)
    assert isinstance(decoded, dict)
    return decoded


def _config(tmp_path: Path, certificates: CertificateBundle) -> CollectorConfig:
    allowlist = tmp_path / "nodes.yaml"
    allowlist.write_text("nodes:\n  - node-01\n", encoding="utf-8")
    return CollectorConfig(
        tls=TLSConfig(
            ca_cert=certificates.ca_cert,
            server_cert=certificates.server.cert,
            server_key=certificates.server.key,
        ),
        allowlist_path=allowlist,
        server=ServerConfig(
            host="127.0.0.1",
            port=0,
            handshake_timeout_seconds=2,
            read_timeout_seconds=2,
        ),
    )


async def _with_server(
    config: CollectorConfig,
    event_logger: Callable[[CSIEvent], None] | None,
    operation: Callable[[CollectorServer], Any],
) -> Any:
    server = CollectorServer(config, event_logger=event_logger)
    await server.start()
    try:
        return await operation(server)
    finally:
        await server.close()


def _configure_forensics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Ed25519PublicKey]:
    store = tmp_path / "chain.jsonl"
    private_key = tmp_path / "forensics-private.pem"
    signer = generate_signing_key()
    save_private_key(signer, private_key)
    monkeypatch.setenv("VESTRIX_FORENSICS_STORE", str(store))
    monkeypatch.setenv("VESTRIX_FORENSICS_PRIVATE_KEY", str(private_key))
    return store, signer.public_key()


def test_valid_certificate_and_enrolled_node_is_accepted(
    tmp_path: Path, certificates: CertificateBundle
) -> None:
    received: list[CSIEvent] = []

    async def scenario(server: CollectorServer) -> dict[str, str]:
        return await asyncio.to_thread(
            _send_event,
            server.port,
            certificates.ca_cert,
            certificates.enrolled_node,
            _payload(),
        )

    response = asyncio.run(
        _with_server(_config(tmp_path, certificates), received.append, scenario)
    )

    assert response == {
        "status": "accepted",
        "reason": "authenticated_event_handed_off",
    }
    assert received == [_payload()]


def test_default_adapter_appends_verifiable_accepted_event(
    tmp_path: Path,
    certificates: CertificateBundle,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, public_key = _configure_forensics(tmp_path, monkeypatch)

    async def scenario(server: CollectorServer) -> dict[str, str]:
        return await asyncio.to_thread(
            _send_event,
            server.port,
            certificates.ca_cert,
            certificates.enrolled_node,
            _payload(),
        )

    response = asyncio.run(
        _with_server(_config(tmp_path, certificates), None, scenario)
    )
    record = json.loads(store.read_text(encoding="utf-8"))

    assert response["status"] == "accepted"
    assert verify_chain(store, public_key).records_verified == 1
    assert record["raw_csi_hash"] == _payload()["csi_window_sha256"]
    assert record["format_version"] == 2
    assert record["event_type"] == "ingestion_accepted"
    assert record["collector_sequence_number"] == 1
    assert not {
        "features_hash",
        "model_id",
        "model_config_hash",
        "class",
        "confidence",
        "top_shap",
    } & record.keys()


def test_default_adapter_chains_two_accepted_events(
    tmp_path: Path,
    certificates: CertificateBundle,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, public_key = _configure_forensics(tmp_path, monkeypatch)

    async def scenario(server: CollectorServer) -> list[dict[str, str]]:
        return [
            await asyncio.to_thread(
                _send_event,
                server.port,
                certificates.ca_cert,
                certificates.enrolled_node,
                _payload(sequence_number),
            )
            for sequence_number in (1, 2)
        ]

    responses = asyncio.run(
        _with_server(_config(tmp_path, certificates), None, scenario)
    )
    records = [
        json.loads(line)
        for line in store.read_text(encoding="utf-8").splitlines()
    ]

    assert [response["status"] for response in responses] == ["accepted", "accepted"]
    assert verify_chain(store, public_key).records_verified == 2
    assert records[1]["prev_hash"] == records[0]["record_hash"]


def test_rejected_replay_is_not_appended_to_forensic_chain(
    tmp_path: Path,
    certificates: CertificateBundle,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, public_key = _configure_forensics(tmp_path, monkeypatch)
    caplog.set_level(logging.INFO, logger="vestrix_collector.decisions")

    async def scenario(server: CollectorServer) -> list[dict[str, str]]:
        return [
            await asyncio.to_thread(
                _send_event,
                server.port,
                certificates.ca_cert,
                certificates.enrolled_node,
                _payload(),
            )
            for _ in range(2)
        ]

    responses = asyncio.run(
        _with_server(_config(tmp_path, certificates), None, scenario)
    )

    assert responses[0]["status"] == "accepted"
    assert responses[1] == {
        "status": "rejected",
        "reason": "replayed_or_out_of_order_sequence",
    }
    assert verify_chain(store, public_key).records_verified == 1
    assert any(
        getattr(record, "decision_fields", {}).get("reason")
        == "replayed_or_out_of_order_sequence"
        for record in caplog.records
    )


def test_forensic_append_failure_rejects_event(
    tmp_path: Path,
    certificates: CertificateBundle,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, _ = _configure_forensics(tmp_path, monkeypatch)
    caplog.set_level(logging.INFO, logger="vestrix_collector.decisions")
    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("VESTRIX_FORENSICS_STORE", str(blocked_parent / store.name))

    async def scenario(server: CollectorServer) -> dict[str, str]:
        return await asyncio.to_thread(
            _send_event,
            server.port,
            certificates.ca_cert,
            certificates.enrolled_node,
            _payload(),
        )

    response = asyncio.run(
        _with_server(_config(tmp_path, certificates), None, scenario)
    )

    assert response == {"status": "rejected", "reason": "forensics_handoff_failed"}
    assert not (blocked_parent / store.name).exists()
    assert any(
        getattr(record, "decision_fields", {}).get("reason")
        == "forensics_handoff_failed"
        for record in caplog.records
    )


def test_valid_certificate_with_unenrolled_cn_is_rejected(
    tmp_path: Path, certificates: CertificateBundle
) -> None:
    received: list[CSIEvent] = []

    async def scenario(server: CollectorServer) -> dict[str, str]:
        return await asyncio.to_thread(
            _send_event,
            server.port,
            certificates.ca_cert,
            certificates.unenrolled_node,
            None,
        )

    response = asyncio.run(
        _with_server(_config(tmp_path, certificates), received.append, scenario)
    )

    assert response == {
        "status": "rejected",
        "reason": "unenrolled_certificate_cn",
    }
    assert received == []


def test_self_signed_client_certificate_is_rejected_during_tls(
    tmp_path: Path,
    certificates: CertificateBundle,
    caplog: pytest.LogCaptureFixture,
) -> None:
    received: list[CSIEvent] = []
    caplog.set_level(logging.INFO, logger="vestrix_collector.decisions")

    async def scenario(server: CollectorServer) -> None:
        with pytest.raises(ssl.SSLError):
            await asyncio.to_thread(
                _send_event,
                server.port,
                certificates.ca_cert,
                certificates.self_signed_node,
                _payload(),
            )
        for _ in range(100):
            if any(
                getattr(record, "decision_fields", {}).get("reason")
                == "tls_handshake_failed"
                for record in caplog.records
            ):
                return
            await asyncio.sleep(0.01)
        pytest.fail("server did not emit a TLS rejection decision")

    asyncio.run(
        _with_server(_config(tmp_path, certificates), received.append, scenario)
    )
    assert received == []


def test_replayed_sequence_number_is_rejected(
    tmp_path: Path, certificates: CertificateBundle
) -> None:
    received: list[CSIEvent] = []

    async def scenario(server: CollectorServer) -> list[dict[str, str]]:
        first = await asyncio.to_thread(
            _send_event,
            server.port,
            certificates.ca_cert,
            certificates.enrolled_node,
            _payload(7),
        )
        replay = await asyncio.to_thread(
            _send_event,
            server.port,
            certificates.ca_cert,
            certificates.enrolled_node,
            _payload(7),
        )
        return [first, replay]

    responses = asyncio.run(
        _with_server(_config(tmp_path, certificates), received.append, scenario)
    )

    assert responses == [
        {"status": "accepted", "reason": "authenticated_event_handed_off"},
        {"status": "rejected", "reason": "replayed_or_out_of_order_sequence"},
    ]
    assert received == [_payload(7)]
