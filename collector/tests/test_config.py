from pathlib import Path

from vestrix_collector.config import load_config


def test_crl_path_is_resolved_from_collector_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        """tls:
  ca_cert: ca.crt
  crl_path: ca.crl
  server_cert: server.crt
  server_key: server.key
allowlist_path: nodes.yaml
server:
  host: 127.0.0.1
  port: 8443
""",
        encoding="utf-8",
    )

    assert load_config(config_path).tls.crl_path == tmp_path / "ca.crl"
