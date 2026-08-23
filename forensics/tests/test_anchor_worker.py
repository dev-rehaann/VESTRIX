from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    PendingAttestation,
)
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from forensics.anchor import (
    AnchorConfigurationError,
    AnchorTransientError,
    OpenTimestampsBackend,
    inspect_proof,
)
from forensics.anchor_worker import (
    BACKOFF_FINAL_MAX_SECONDS,
    INDEPENDENTLY_VERIFIED,
    QUEUED,
    RETRY_FAILED,
    SUBMITTED_PENDING,
    UPGRADED_UNVERIFIED,
    LifecycleStore,
    WorkerConfig,
    retry_delay_seconds,
    run_once,
)
from forensics.logger import log_event


def _serialize(detached: DetachedTimestampFile) -> bytes:
    context = BytesSerializationContext()
    detached.serialize(context)
    return context.getbytes()


def _proof_for(digest: bytes, *, bitcoin: bool) -> bytes:
    detached = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    commitment = detached.timestamp.ops.add(OpAppend(b"n" * 16)).ops.add(OpSHA256())
    attestation = (
        BitcoinBlockHeaderAttestation(900_000)
        if bitcoin
        else PendingAttestation("https://alice.btc.calendar.opentimestamps.org")
    )
    commitment.attestations.add(attestation)
    return _serialize(detached)


class _FakeBackend:
    def __init__(
        self,
        stamp_result: bytes | Exception,
        upgrade_result: bytes | Exception | None = None,
    ) -> None:
        self.stamp_result = stamp_result
        self.upgrade_result = upgrade_result
        self.stamp_calls = 0
        self.upgrade_calls = 0

    def stamp(self, digest: bytes) -> bytes:
        self.stamp_calls += 1
        if isinstance(self.stamp_result, Exception):
            raise self.stamp_result
        return self.stamp_result

    def upgrade(self, proof: bytes, digest: bytes) -> bytes | None:
        self.upgrade_calls += 1
        if isinstance(self.upgrade_result, Exception):
            raise self.upgrade_result
        return self.upgrade_result


def _setup_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> tuple[WorkerConfig, dict[str, Any]]:
    chain = tmp_path / "chain.jsonl"
    monkeypatch.setenv("VESTRIX_FORENSICS_STORE", str(chain))
    record = log_event(event_factory(0), Ed25519PrivateKey.generate())
    return (
        WorkerConfig(
            chain_path=chain,
            database_path=tmp_path / "anchors.sqlite3",
            proof_directory=tmp_path / "proofs",
        ),
        record,
    )


def _row(config: WorkerConfig, record: dict[str, Any]) -> dict[str, Any]:
    with LifecycleStore(config.database_path) as store:
        return dict(store.get(record["seq"], record["record_hash"]))


def test_backend_preserves_chain_tip_digest_without_extra_hash() -> None:
    digest = bytes.fromhex("42" * 32)
    submitted: list[Timestamp] = []

    def submit(timestamp: Timestamp) -> None:
        submitted.append(timestamp)
        timestamp.attestations.add(PendingAttestation("https://example.invalid"))

    proof = OpenTimestampsBackend(
        submitter=submit,
        nonce_factory=lambda length: b"n" * length,
    ).stamp(digest)
    detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))

    assert detached.file_digest == digest
    assert detached.timestamp.msg == digest
    assert submitted[0].msg != digest


def test_backend_upgrade_adds_returned_bitcoin_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentimestamps.calendar as calendar_module

    digest = bytes.fromhex("42" * 32)
    proof = _proof_for(digest, bitcoin=False)

    class ReadyCalendar:
        def __init__(self, uri: str, user_agent: str) -> None:
            assert uri == "https://alice.btc.calendar.opentimestamps.org"
            assert user_agent == "OpenTimestamps-Client/0.7.2"

        def get_timestamp(self, commitment: bytes) -> Timestamp:
            upgraded = Timestamp(commitment)
            upgraded.attestations.add(BitcoinBlockHeaderAttestation(900_000))
            return upgraded

    monkeypatch.setattr(calendar_module, "RemoteCalendar", ReadyCalendar)
    upgraded = OpenTimestampsBackend().upgrade(proof, digest)

    assert upgraded is not None
    assert inspect_proof(upgraded, digest).has_bitcoin_attestation


def test_backend_upgrade_treats_commitment_not_found_as_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentimestamps.calendar as calendar_module

    digest = bytes.fromhex("42" * 32)
    proof = _proof_for(digest, bitcoin=False)

    class PendingCalendar:
        def __init__(self, uri: str, user_agent: str) -> None:
            pass

        def get_timestamp(self, commitment: bytes) -> Timestamp:
            raise calendar_module.CommitmentNotFoundError("not ready")

    monkeypatch.setattr(calendar_module, "RemoteCalendar", PendingCalendar)

    assert OpenTimestampsBackend().upgrade(proof, digest) is None


def test_backend_upgrade_surfaces_network_timeout_as_transient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentimestamps.calendar as calendar_module

    digest = bytes.fromhex("42" * 32)
    proof = _proof_for(digest, bitcoin=False)

    class TimedOutCalendar:
        def __init__(self, uri: str, user_agent: str) -> None:
            pass

        def get_timestamp(self, commitment: bytes) -> Timestamp:
            raise TimeoutError("calendar timed out")

    monkeypatch.setattr(calendar_module, "RemoteCalendar", TimedOutCalendar)

    with pytest.raises(AnchorTransientError, match="calendar timed out"):
        OpenTimestampsBackend().upgrade(proof, digest)


@pytest.mark.parametrize(
    ("quorum", "calendar_urls"),
    [(0, ("https://one", "https://two")), (2, ("https://one",))],
)
def test_backend_prevalidates_client_quorum_before_submission(
    quorum: int,
    calendar_urls: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentimestamps.calendar as calendar_module
    import otsclient.args as args_module
    import otsclient.cmds as cmds_module

    called = False

    def should_not_submit(*args: Any, **kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(calendar_module, "DEFAULT_AGGREGATORS", calendar_urls)
    monkeypatch.setattr(
        args_module,
        "parse_ots_args",
        lambda raw_args: SimpleNamespace(m=quorum),
    )
    monkeypatch.setattr(cmds_module, "create_timestamp", should_not_submit)

    with pytest.raises(AnchorConfigurationError, match=f"quorum {quorum} is invalid"):
        OpenTimestampsBackend().stamp(bytes.fromhex("42" * 32))

    assert not called


def test_create_timestamp_quorum_exit_becomes_transient_worker_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    import otsclient.cmds as cmds_module

    def quorum_not_met(*args: Any, **kwargs: Any) -> None:
        raise SystemExit(1)

    monkeypatch.setattr(cmds_module, "create_timestamp", quorum_not_met)
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)

    assert run_once(
        config,
        now=datetime(2026, 8, 23, tzinfo=UTC),
        jitter_sample=0.0,
    ) == 1

    row = _row(config, record)
    assert row["state"] == RETRY_FAILED
    assert row["failure_class"] == "transient"
    assert row["retry_from"] == QUEUED
    assert row["last_error"] == "OpenTimestamps calendar quorum failed"


def test_queued_transitions_to_submitted_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    backend = _FakeBackend(_proof_for(digest, bitcoin=False))
    now = datetime(2026, 8, 23, tzinfo=UTC)

    assert run_once(config, backend, now=now, jitter_sample=0.0) == 1

    row = _row(config, record)
    assert row["state"] == SUBMITTED_PENDING
    assert row["attempt_count"] == 0
    assert row["interval_minutes"] == 15
    assert row["confirmation_threshold"] == 6
    assert row["verified_height"] is None
    assert Path(row["proof_path"]).read_bytes() == backend.stamp_result


def test_queued_transitions_to_upgraded_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])

    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=True)),
        now=datetime(2026, 8, 23, tzinfo=UTC),
        jitter_sample=0.0,
    )

    assert _row(config, record)["state"] == UPGRADED_UNVERIFIED


def test_submitted_pending_transitions_to_upgraded_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    now = datetime(2026, 8, 23, tzinfo=UTC)
    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=False)),
        now=now,
        jitter_sample=0.0,
    )

    upgraded = _proof_for(digest, bitcoin=True)
    backend = _FakeBackend(b"unused", upgrade_result=upgraded)
    run_once(config, backend, now=now + timedelta(minutes=15), jitter_sample=0.0)

    row = _row(config, record)
    assert row["state"] == UPGRADED_UNVERIFIED
    assert Path(row["proof_path"]).read_bytes() == upgraded
    assert backend.upgrade_calls == 1


def test_calendar_not_ready_remains_submitted_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    now = datetime(2026, 8, 23, tzinfo=UTC)
    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=False)),
        now=now,
        jitter_sample=0.0,
    )

    backend = _FakeBackend(b"unused", upgrade_result=None)
    run_once(config, backend, now=now + timedelta(minutes=15), jitter_sample=0.0)

    row = _row(config, record)
    assert row["state"] == SUBMITTED_PENDING
    assert row["failure_class"] is None
    assert row["attempt_count"] == 0
    assert backend.upgrade_calls == 1


@pytest.mark.parametrize("failure_kind", ["transient", "integrity"])
def test_failure_transitions_to_retry_failed_with_correct_classification(
    failure_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    result: bytes | Exception = (
        TimeoutError("calendar timed out")
        if failure_kind == "transient"
        else _proof_for(bytes.fromhex("ff" * 32), bitcoin=False)
    )
    now = datetime(2026, 8, 23, tzinfo=UTC)

    run_once(config, _FakeBackend(result), now=now, jitter_sample=1.0)

    row = _row(config, record)
    assert row["state"] == RETRY_FAILED
    assert row["failure_class"] == failure_kind
    assert row["retry_from"] == QUEUED
    assert row["attempt_count"] == 1
    if failure_kind == "transient":
        assert row["next_attempt"] == "2026-08-23T00:18:45.000000Z"
    else:
        assert row["next_attempt"] is None
        assert "does not match chain tip" in row["last_error"]


def test_transient_retry_resumes_from_recorded_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    now = datetime(2026, 8, 23, tzinfo=UTC)
    run_once(
        config,
        _FakeBackend(TimeoutError("calendar timed out")),
        now=now,
        jitter_sample=0.0,
    )
    digest = bytes.fromhex(record["record_hash"])

    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=False)),
        now=now + timedelta(minutes=15),
        jitter_sample=0.0,
    )

    row = _row(config, record)
    assert row["state"] == SUBMITTED_PENDING
    assert row["attempt_count"] == 1
    assert row["retry_from"] is None


def test_pending_upgrade_timeout_transitions_to_retry_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    now = datetime(2026, 8, 23, tzinfo=UTC)
    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=False)),
        now=now,
        jitter_sample=0.0,
    )

    run_once(
        config,
        _FakeBackend(b"unused", upgrade_result=TimeoutError("upgrade timed out")),
        now=now + timedelta(minutes=15),
        jitter_sample=0.0,
    )

    row = _row(config, record)
    assert row["state"] == RETRY_FAILED
    assert row["failure_class"] == "transient"
    assert row["retry_from"] == SUBMITTED_PENDING
    assert row["attempt_count"] == 1


def test_pending_proof_corruption_transitions_to_integrity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    now = datetime(2026, 8, 23, tzinfo=UTC)
    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=False)),
        now=now,
        jitter_sample=0.0,
    )
    Path(_row(config, record)["proof_path"]).write_bytes(b"corrupt")

    run_once(
        config,
        _FakeBackend(b"unused"),
        now=now + timedelta(minutes=15),
        jitter_sample=0.0,
    )

    row = _row(config, record)
    assert row["state"] == RETRY_FAILED
    assert row["failure_class"] == "integrity"
    assert row["retry_from"] == SUBMITTED_PENDING
    assert row["next_attempt"] is None


def test_sequence_tip_uniqueness_constraint(tmp_path: Path) -> None:
    database = tmp_path / "anchors.sqlite3"
    proof = tmp_path / "proof.ots"
    with LifecycleStore(database) as store:
        store.track_tip(7, "ab" * 32, proof, 15, 6)
        store.track_tip(7, "ab" * 32, proof, 30, 12)

        assert store.count(7, "ab" * 32) == 1
        row = store.get(7, "ab" * 32)
        assert row["interval_minutes"] == 15
        assert row["confirmation_threshold"] == 6


def test_worker_recovers_after_proof_write_before_database_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    backend = _FakeBackend(_proof_for(digest, bitcoin=False))
    original_transition = LifecycleStore.transition

    def interrupt_after_write(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as interruption:
        interruption.setattr(LifecycleStore, "transition", interrupt_after_write)
        with pytest.raises(KeyboardInterrupt):
            run_once(
                config,
                backend,
                now=datetime(2026, 8, 23, tzinfo=UTC),
                jitter_sample=0.0,
            )

    assert _row(config, record)["state"] == QUEUED
    assert backend.stamp_calls == 1
    assert list(config.proof_directory.glob("*.ots"))

    assert LifecycleStore.transition is original_transition
    run_once(
        config,
        backend,
        now=datetime(2026, 8, 23, tzinfo=UTC),
        jitter_sample=0.0,
    )

    assert _row(config, record)["state"] == SUBMITTED_PENDING
    assert backend.stamp_calls == 1


def test_worker_recovers_after_upgraded_proof_write_before_database_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: Any,
) -> None:
    config, record = _setup_chain(tmp_path, monkeypatch, event_factory)
    digest = bytes.fromhex(record["record_hash"])
    now = datetime(2026, 8, 23, tzinfo=UTC)
    run_once(
        config,
        _FakeBackend(_proof_for(digest, bitcoin=False)),
        now=now,
        jitter_sample=0.0,
    )
    backend = _FakeBackend(
        b"unused",
        upgrade_result=_proof_for(digest, bitcoin=True),
    )

    def interrupt_after_write(*args: Any, **kwargs: Any) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as interruption:
        interruption.setattr(LifecycleStore, "transition", interrupt_after_write)
        with pytest.raises(KeyboardInterrupt):
            run_once(
                config,
                backend,
                now=now + timedelta(minutes=15),
                jitter_sample=0.0,
            )

    assert _row(config, record)["state"] == SUBMITTED_PENDING
    assert backend.upgrade_calls == 1

    recovery_backend = _FakeBackend(b"unused")
    run_once(
        config,
        recovery_backend,
        now=now + timedelta(minutes=15),
        jitter_sample=0.0,
    )

    assert _row(config, record)["state"] == UPGRADED_UNVERIFIED
    assert recovery_backend.upgrade_calls == 0


def test_retry_backoff_uses_confirmed_formula_and_cap() -> None:
    assert retry_delay_seconds(1, 0.0) == 900
    assert retry_delay_seconds(1, 1.0) == 1_125
    assert retry_delay_seconds(2, 0.0) == 1_800
    assert retry_delay_seconds(8, 0.5) == 100_800
    assert retry_delay_seconds(8, 1.0) == BACKOFF_FINAL_MAX_SECONDS
    assert retry_delay_seconds(20, 1.0) == BACKOFF_FINAL_MAX_SECONDS


def test_independently_verified_has_no_python_transition(tmp_path: Path) -> None:
    with LifecycleStore(tmp_path / "anchors.sqlite3") as store:
        store.track_tip(0, "ab" * 32, tmp_path / "proof.ots", 15, 6)
        queued = store.get(0, "ab" * 32)
        upgraded = store.transition(
            queued,
            UPGRADED_UNVERIFIED,
            "2026-08-23T00:00:00.000000Z",
        )

        with pytest.raises(ValueError, match="forbidden anchor transition"):
            store.transition(
                upgraded,
                INDEPENDENTLY_VERIFIED,
                "2026-08-23T00:00:01.000000Z",
            )
