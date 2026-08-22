from __future__ import annotations

import json
import os
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from forensics._format import (
    GENESIS_PREV_HASH,
    canonical_json_bytes,
    hash_unsigned_record,
)
from forensics.anchor import anchor_chain_tip
from forensics.chain_check import ChainVerificationError, verify_chain
from forensics.keys import (
    generate_and_save_keypair,
    generate_signing_key,
    load_private_key,
    load_public_key,
)
from forensics.logger import AppendError, log_event

EventFactory = Callable[[int], dict[str, Any]]


def _configure_store(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("VESTRIX_FORENSICS_STORE", str(path))


def _process_writer(store_path: str, key_path: str, writer_id: int, count: int) -> None:
    os.environ["VESTRIX_FORENSICS_STORE"] = store_path
    signer = load_private_key(key_path)
    for offset in range(count):
        unique = writer_id * 1_000 + offset
        digest = f"{unique:064x}"
        log_event(
            {
                "format_version": 2,
                "event_type": "classification_decision",
                "ts_utc": f"2026-07-13T13:00:{offset % 60:02d}Z",
                "node_id": f"writer-{writer_id}",
                "raw_csi_hash": digest,
                "features_hash": digest,
                "model_id": "concurrency-test",
                "model_config_hash": "a" * 64,
                "class": "normal",
                "confidence": 0.9,
                "top_shap": [],
            },
            signer,
        )


def test_interoperability_vector_matches_specification() -> None:
    unsigned = {
        "format_version": 2,
        "event_type": "classification_decision",
        "seq": 0,
        "ts_utc": "2026-07-13T12:00:00Z",
        "node_id": "node-01",
        "raw_csi_hash": "1" * 64,
        "features_hash": "2" * 64,
        "model_id": "model-v1",
        "model_config_hash": "3" * 64,
        "class": "normal",
        "confidence": 0.875,
        "top_shap": [],
        "prev_hash": "0" * 64,
    }
    expected_hash = "a3cf276f603ad38d4c36c6319a47f1aaf618ace6c00a5da65d33cbd3caaa6efb"
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        )
    )
    signature = bytes.fromhex(
        "e24926670ba994607ddabd50de2506d4e916ace4f35cc470e545015f512262d91"
        "22baf4e44a5db6ca5923f18ee2be9286d6f840bc8310fd882dd24fedafdd00d"
    )

    record_bytes, record_hash = hash_unsigned_record(unsigned)

    assert record_hash == expected_hash
    assert record_bytes.startswith(
        b'{"class":"normal","confidence":0.875,'
        b'"event_type":"classification_decision",'
    )
    assert record_bytes.endswith(b'"ts_utc":"2026-07-13T12:00:00Z"}')
    public_key.verify(signature, record_bytes)


@pytest.mark.parametrize(
    ("confidence", "expected_token", "expected_hash", "expected_signature"),
    [
        (
            1.0,
            "1.0",
            "1fb4432bfe63a9cf6b54e8ae416ec5d11bd87d6669b527d8c801e54500c4287f",
            "e2a179bc96914aecd5b680659f3158e6067adb64fb20a286a9690de84c56df71"
            "41ee3e3d1681d1c129a3f92685c1023baf04f642fbdfcb3aefdbf9bd9ef63f03",
        ),
        (
            0.9532,
            "0.9532",
            "5d6c9cc40f8db9dcf9984ce87cc7889eec0e0694426d0a3d20e97efaa739afc7",
            "b61ad135f9ea5fa3894646c74b4f6b6c410daa10bc7c47feb1a8a288b9bedf6e"
            "fcbd93ce8291c798048899f0a428123ef9acc6c4838bce1372c9978705012c04",
        ),
        (
            0.1 + 0.2,
            "0.30000000000000004",
            "576598c9ed876b0d040e3d1149883994d0f7e4f1f7800605d9d2552237e72ab6",
            "33344ebde2b8cb80741e9e74e64c26342be691fb1924c0389ba802903d473b09"
            "49c54a91f837534881386f6e21293ccac5ade1764542c584eb1ae6ccc888ff0b",
        ),
        (
            0.00001,
            "1e-05",
            "e6019ec3fc79d8c4e22ae378cdd5a8a1753f6bbb36ac847959e34031fae083cf",
            "4545cf6255c52fe1a8ea9849621ac8c3a812570534057681227d212b2274535e"
            "0cbea61e30c8565d695fd9308a155093e546d67b81039a21bf9fc4f5edc53d0a",
        ),
    ],
)
def test_binary64_interoperability_vectors_match_specification(
    confidence: float,
    expected_token: str,
    expected_hash: str,
    expected_signature: str,
) -> None:
    unsigned = {
        "format_version": 2,
        "event_type": "classification_decision",
        "seq": 0,
        "ts_utc": "2026-07-13T12:00:00Z",
        "node_id": "node-01",
        "raw_csi_hash": "1" * 64,
        "features_hash": "2" * 64,
        "model_id": "model-v1",
        "model_config_hash": "3" * 64,
        "class": "normal",
        "confidence": confidence,
        "top_shap": [],
        "prev_hash": "0" * 64,
    }
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    rendered = json.dumps(
        confidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    record_bytes, record_hash = hash_unsigned_record(unsigned)

    assert rendered == expected_token
    assert f'"confidence":{expected_token},'.encode() in record_bytes
    assert record_hash == expected_hash
    assert signer.sign(record_bytes).hex() == expected_signature


def test_valid_chain_passes_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()

    records = [log_event(event_factory(index), signer) for index in range(4)]
    result = verify_chain(store, signer.public_key())

    assert result.records_verified == 4
    assert result.tip_hash == records[-1]["record_hash"]


def test_v2_ingestion_and_classification_records_share_one_valid_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    ingestion = {
        "format_version": 2,
        "event_type": "ingestion_accepted",
        "ts_utc": "2026-07-13T12:00:00Z",
        "node_id": "node-01",
        "raw_csi_hash": "1" * 64,
        "collector_schema_version": "0.1",
        "collector_sequence_number": 42,
    }

    accepted = log_event(ingestion, signer)
    classified = log_event(event_factory(1), signer)
    result = verify_chain(store, signer.public_key())

    assert result.records_verified == 2
    assert accepted["event_type"] == "ingestion_accepted"
    assert not {
        "features_hash",
        "model_id",
        "model_config_hash",
        "class",
        "confidence",
        "top_shap",
    } & accepted.keys()
    assert classified["event_type"] == "classification_decision"
    assert classified["prev_hash"] == accepted["record_hash"]


def test_legacy_v1_record_remains_verifiable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    legacy_event = {
        "ts_utc": "2026-07-13T12:00:00Z",
        "node_id": "node-01",
        "raw_csi_hash": "1" * 64,
        "features_hash": "2" * 64,
        "model_id": "model-v1",
        "model_config_hash": "3" * 64,
        "class": "normal",
        "confidence": 0.875,
        "top_shap": [],
    }

    record = log_event(legacy_event, signer)

    assert "format_version" not in record
    assert verify_chain(store, signer.public_key()).records_verified == 1


def test_writer_refuses_to_mix_v1_and_v2_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    legacy_event = dict(event_factory(0))
    legacy_event.pop("format_version")
    legacy_event.pop("event_type")
    log_event(legacy_event, signer)

    with pytest.raises(AppendError, match="different format version"):
        log_event(event_factory(1), signer)

    assert verify_chain(store, signer.public_key()).records_verified == 1


def test_every_single_byte_flip_in_historical_record_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    for index in range(2):
        log_event(event_factory(index), signer)
    original = store.read_bytes()

    for position in range(len(original)):
        tampered = bytearray(original)
        tampered[position] ^= 1
        store.write_bytes(tampered)
        with pytest.raises(ChainVerificationError):
            verify_chain(store, signer.public_key())

    store.write_bytes(original)
    assert verify_chain(store, signer.public_key()).records_verified == 2


def test_valid_hash_with_invalid_signature_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    log_event(event_factory(1), signer)

    record = json.loads(store.read_bytes())
    record["class"] = "tampered-but-rehashed"
    _, record["record_hash"] = hash_unsigned_record(record)
    store.write_bytes(canonical_json_bytes(record) + b"\n")

    with pytest.raises(ChainVerificationError, match="signature"):
        verify_chain(store, signer.public_key())


def test_genesis_record_uses_documented_sentinel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()

    genesis = log_event(event_factory(0), signer)

    assert genesis["seq"] == 0
    assert genesis["prev_hash"] == GENESIS_PREV_HASH == "0" * 64
    assert verify_chain(store, signer.public_key()).records_verified == 1


def test_concurrent_process_writers_do_not_lose_or_corrupt_records(
    tmp_path: Path,
) -> None:
    store = tmp_path / "chain.jsonl"
    private_path = tmp_path / "logger.pem"
    public_path = tmp_path / "logger.pub.pem"
    generate_and_save_keypair(private_path, public_path)
    writers = 2
    per_writer = 12

    with ProcessPoolExecutor(max_workers=writers) as pool:
        futures = [
            pool.submit(
                _process_writer,
                str(store),
                str(private_path),
                writer_id,
                per_writer,
            )
            for writer_id in range(writers)
        ]
        for future in futures:
            future.result(timeout=30)

    result = verify_chain(store, load_public_key(public_path))
    lines = store.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert result.records_verified == writers * per_writer
    assert [record["seq"] for record in records] == list(range(writers * per_writer))
    assert len({record["raw_csi_hash"] for record in records}) == writers * per_writer


def test_key_helpers_round_trip_without_overwriting(tmp_path: Path) -> None:
    private_path = tmp_path / "keys" / "logger.pem"
    public_path = tmp_path / "keys" / "logger.pub.pem"
    generate_and_save_keypair(private_path, public_path, b"test-password")

    private_key = load_private_key(private_path, b"test-password")
    public_key = load_public_key(public_path)
    message = b"public verification test"
    public_key.verify(private_key.sign(message), message)

    with pytest.raises(FileExistsError):
        generate_and_save_keypair(private_path, public_path)


class _FakeTimestampBackend:
    def stamp(self, digest: bytes) -> bytes:
        assert len(digest) == 32
        return b"fake-ots-proof:" + digest


def test_anchor_interface_snapshots_tip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    proof = tmp_path / "anchors" / "tip.ots"
    _configure_store(monkeypatch, store)
    signer = Ed25519PrivateKey.generate()
    record = log_event(event_factory(0), signer)

    receipt = anchor_chain_tip(store, proof, _FakeTimestampBackend())

    assert receipt.sequence == 0
    assert receipt.tip_hash == record["record_hash"]
    assert proof.read_bytes().endswith(bytes.fromhex(record["record_hash"]))
