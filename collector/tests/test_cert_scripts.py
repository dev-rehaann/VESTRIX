from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from vestrix_collector.config import CollectorConfig, ServerConfig, TLSConfig
from vestrix_collector.server import CollectorServer


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux OpenSSL tooling")
def test_fresh_ca_bootstrap_creates_empty_loadable_crl(tmp_path: Path) -> None:
    cert_tools = Path(__file__).parents[1] / "certs"
    shutil.copy(cert_tools / "generate_ca.sh", tmp_path)
    shutil.copy(cert_tools / "openssl.cnf", tmp_path)
    subprocess.run(
        ["bash", "generate_ca.sh"], cwd=tmp_path, check=True, capture_output=True
    )

    crl_text = subprocess.run(
        ["openssl", "crl", "-in", "ca.crl", "-noout", "-text"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Serial Number:" not in crl_text

    subprocess.run(
        ["openssl", "genrsa", "-out", "server.key", "2048"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=collector-test",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "2000",
            "-out",
            "server.crt",
            "-days",
            "1",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    allowlist = tmp_path / "nodes.yaml"
    allowlist.write_text("nodes:\n  - node-01\n", encoding="utf-8")
    config = CollectorConfig(
        tls=TLSConfig(
            ca_cert=tmp_path / "ca.crt",
            crl_path=tmp_path / "ca.crl",
            server_cert=tmp_path / "server.crt",
            server_key=tmp_path / "server.key",
        ),
        allowlist_path=allowlist,
        server=ServerConfig(host="127.0.0.1", port=0),
    )

    async def start_and_close() -> None:
        server = CollectorServer(config)
        await server.start()
        assert server.port > 0
        await server.close()

    asyncio.run(start_and_close())
