"""One-shot OpenTimestamps lifecycle worker."""

from __future__ import annotations

import argparse
import logging
import random
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from filelock import FileLock

from ._store import chain_tip
from .anchor import (
    AnchorConfigurationError,
    AnchorIntegrityError,
    OpenTimestampsBackend,
    TimestampBackend,
    inspect_proof,
    write_proof_atomic,
)
from .logger import LOCK_TIMEOUT_SECONDS, get_store_path, lock_path_for

LOGGER = logging.getLogger(__name__)

DEFAULT_INTERVAL_MINUTES = 15
DEFAULT_CONFIRMATION_THRESHOLD = 6
BACKOFF_BASE_SECONDS = 15 * 60
BACKOFF_MAX_SECONDS = 24 * 60 * 60
BACKOFF_JITTER_RATIO = 0.25
BACKOFF_FINAL_MAX_SECONDS = BACKOFF_MAX_SECONDS * 1.25

QUEUED = "queued"
SUBMITTED_PENDING = "submitted_pending"
UPGRADED_UNVERIFIED = "upgraded_unverified"
INDEPENDENTLY_VERIFIED = "independently_verified"
RETRY_FAILED = "retry_failed"

STATES = (
    QUEUED,
    SUBMITTED_PENDING,
    UPGRADED_UNVERIFIED,
    INDEPENDENTLY_VERIFIED,
    RETRY_FAILED,
)
RETRY_SOURCES = (QUEUED, SUBMITTED_PENDING, UPGRADED_UNVERIFIED)
ALLOWED_TRANSITIONS = {
    QUEUED: {SUBMITTED_PENDING, UPGRADED_UNVERIFIED, RETRY_FAILED},
    SUBMITTED_PENDING: {UPGRADED_UNVERIFIED, RETRY_FAILED},
    UPGRADED_UNVERIFIED: {RETRY_FAILED},
    RETRY_FAILED: set(RETRY_SOURCES),
    INDEPENDENTLY_VERIFIED: set(),
}


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    """Paths and locked lifecycle settings for one worker invocation."""

    chain_path: Path
    database_path: Path
    proof_directory: Path
    interval_minutes: int = DEFAULT_INTERVAL_MINUTES
    confirmation_threshold: int = DEFAULT_CONFIRMATION_THRESHOLD

    def __post_init__(self) -> None:
        if self.interval_minutes <= 0:
            raise ValueError("interval_minutes must be positive")
        if self.confirmation_threshold <= 0:
            raise ValueError("confirmation_threshold must be positive")


class LifecycleStore:
    """Transactional SQLite state separate from the immutable forensic chain."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=LOCK_TIMEOUT_SECONDS)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS anchors (
                id INTEGER PRIMARY KEY,
                sequence INTEGER NOT NULL,
                tip_hash TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN {STATES}),
                proof_path TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                last_attempt TEXT,
                next_attempt TEXT,
                last_error TEXT,
                retry_from TEXT CHECK (
                    retry_from IS NULL OR retry_from IN {RETRY_SOURCES}
                ),
                failure_class TEXT CHECK (
                    failure_class IS NULL OR failure_class IN ('transient', 'integrity')
                ),
                verified_height INTEGER,
                verified_hash TEXT,
                verified_time TEXT,
                verified_confirmations INTEGER,
                interval_minutes INTEGER NOT NULL,
                confirmation_threshold INTEGER NOT NULL,
                UNIQUE (sequence, tip_hash)
            )
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> LifecycleStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def track_tip(
        self,
        sequence: int,
        tip_hash: str,
        proof_path: Path,
        interval_minutes: int,
        confirmation_threshold: int,
    ) -> bool:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO anchors (
                sequence, tip_hash, state, proof_path,
                interval_minutes, confirmation_threshold
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                tip_hash,
                QUEUED,
                str(proof_path.expanduser().resolve()),
                interval_minutes,
                confirmation_threshold,
            ),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def get(self, sequence: int, tip_hash: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM anchors WHERE sequence = ? AND tip_hash = ?",
            (sequence, tip_hash),
        ).fetchone()
        if row is None:
            raise KeyError((sequence, tip_hash))
        return row

    def count(self, sequence: int, tip_hash: str) -> int:
        row = self.connection.execute(
            """
            SELECT COUNT(*) AS count FROM anchors
            WHERE sequence = ? AND tip_hash = ?
            """,
            (sequence, tip_hash),
        ).fetchone()
        return int(row["count"])

    def due_jobs(self, now: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                SELECT * FROM anchors
                WHERE state = 'queued'
                   OR (state = 'submitted_pending'
                       AND (next_attempt IS NULL OR next_attempt <= ?))
                   OR (state = 'retry_failed'
                       AND failure_class = 'transient'
                       AND next_attempt IS NOT NULL
                       AND next_attempt <= ?)
                ORDER BY sequence
                """,
                (now, now),
            )
        )

    def transition(
        self,
        job: sqlite3.Row,
        state: str,
        now: str,
        *,
        next_attempt: str | None = None,
    ) -> sqlite3.Row:
        current = str(job["state"])
        if state not in ALLOWED_TRANSITIONS[current]:
            raise ValueError(f"forbidden anchor transition: {current} -> {state}")
        cursor = self.connection.execute(
            """
            UPDATE anchors
            SET state = ?, last_attempt = ?, next_attempt = ?, last_error = NULL,
                retry_from = NULL, failure_class = NULL
            WHERE id = ? AND state = ?
            """,
            (state, now, next_attempt, job["id"], current),
        )
        if cursor.rowcount != 1:
            self.connection.rollback()
            raise RuntimeError("anchor state changed concurrently")
        self.connection.commit()
        return self.get(int(job["sequence"]), str(job["tip_hash"]))

    def pending_checked(
        self, job: sqlite3.Row, now: str, next_attempt: str
    ) -> sqlite3.Row:
        cursor = self.connection.execute(
            """
            UPDATE anchors
            SET last_attempt = ?, next_attempt = ?, last_error = NULL,
                retry_from = NULL, failure_class = NULL
            WHERE id = ? AND state = 'submitted_pending'
            """,
            (now, next_attempt, job["id"]),
        )
        if cursor.rowcount != 1:
            self.connection.rollback()
            raise RuntimeError("anchor state changed concurrently")
        self.connection.commit()
        return self.get(int(job["sequence"]), str(job["tip_hash"]))

    def record_failure(
        self,
        job: sqlite3.Row,
        failure_class: str,
        error: str,
        now: str,
        next_attempt: str | None,
    ) -> sqlite3.Row:
        current = str(job["state"])
        if current not in RETRY_SOURCES:
            raise ValueError(f"cannot fail anchor job from {current}")
        attempt_count = int(job["attempt_count"]) + 1
        cursor = self.connection.execute(
            """
            UPDATE anchors
            SET state = 'retry_failed', attempt_count = ?, last_attempt = ?,
                next_attempt = ?, last_error = ?, retry_from = ?, failure_class = ?
            WHERE id = ? AND state = ?
            """,
            (
                attempt_count,
                now,
                next_attempt,
                error,
                current,
                failure_class,
                job["id"],
                current,
            ),
        )
        if cursor.rowcount != 1:
            self.connection.rollback()
            raise RuntimeError("anchor state changed concurrently")
        self.connection.commit()
        return self.get(int(job["sequence"]), str(job["tip_hash"]))

    def resume_retry(self, job: sqlite3.Row) -> sqlite3.Row:
        retry_from = job["retry_from"]
        if job["state"] != RETRY_FAILED or retry_from not in RETRY_SOURCES:
            raise ValueError("anchor job has no retry source")
        cursor = self.connection.execute(
            """
            UPDATE anchors
            SET state = ?, next_attempt = NULL, failure_class = NULL
            WHERE id = ? AND state = 'retry_failed'
            """,
            (retry_from, job["id"]),
        )
        if cursor.rowcount != 1:
            self.connection.rollback()
            raise RuntimeError("anchor state changed concurrently")
        self.connection.commit()
        return self.get(int(job["sequence"]), str(job["tip_hash"]))


def _utc_text(value: datetime) -> str:
    return (
        value.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def retry_delay_seconds(attempt_count: int, jitter_sample: float) -> float:
    """Return the maintainer-approved capped exponential delay with jitter."""
    if attempt_count < 1:
        raise ValueError("attempt_count must start at 1")
    if not 0.0 <= jitter_sample <= 1.0:
        raise ValueError("jitter sample must be between 0 and 1")
    raw_delay = BACKOFF_BASE_SECONDS * (2 ** (attempt_count - 1))
    capped_delay = min(raw_delay, BACKOFF_MAX_SECONDS)
    jitter = raw_delay * BACKOFF_JITTER_RATIO * jitter_sample
    return min(capped_delay + jitter, BACKOFF_FINAL_MAX_SECONDS)


def snapshot_tip(chain_path: Path) -> tuple[int, str]:
    """Read one validated tip while holding only the existing chain lock."""
    path = chain_path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    with FileLock(str(lock_path_for(path)), timeout=LOCK_TIMEOUT_SECONDS):
        next_sequence, tip_hash = chain_tip(path)
    if next_sequence == 0:
        raise ValueError("cannot anchor an empty chain")
    return next_sequence - 1, tip_hash


def _next_pending_attempt(job: sqlite3.Row, now: datetime) -> str:
    return _utc_text(now + timedelta(minutes=int(job["interval_minutes"])))


def _target_state(proof: bytes, digest: bytes) -> str:
    inspection = inspect_proof(proof, digest)
    return (
        UPGRADED_UNVERIFIED
        if inspection.has_bitcoin_attestation
        else SUBMITTED_PENDING
    )


def _process_queued(
    store: LifecycleStore,
    job: sqlite3.Row,
    backend: TimestampBackend,
    now: datetime,
) -> None:
    digest = bytes.fromhex(str(job["tip_hash"]))
    proof_path = Path(str(job["proof_path"]))
    if proof_path.exists():
        proof = proof_path.read_bytes()
    else:
        proof = backend.stamp(digest)
        target_state = _target_state(proof, digest)
        write_proof_atomic(proof_path, proof, replace=False)
        store.transition(
            job,
            target_state,
            _utc_text(now),
            next_attempt=(
                _next_pending_attempt(job, now)
                if target_state == SUBMITTED_PENDING
                else None
            ),
        )
        return

    target_state = _target_state(proof, digest)
    store.transition(
        job,
        target_state,
        _utc_text(now),
        next_attempt=(
            _next_pending_attempt(job, now)
            if target_state == SUBMITTED_PENDING
            else None
        ),
    )


def _process_pending(
    store: LifecycleStore,
    job: sqlite3.Row,
    backend: TimestampBackend,
    now: datetime,
) -> None:
    digest = bytes.fromhex(str(job["tip_hash"]))
    proof_path = Path(str(job["proof_path"]))
    if not proof_path.exists():
        raise OSError(f"pending proof is missing: {proof_path}")
    current_proof = proof_path.read_bytes()
    if inspect_proof(current_proof, digest).has_bitcoin_attestation:
        store.transition(job, UPGRADED_UNVERIFIED, _utc_text(now))
        return
    upgraded = backend.upgrade(current_proof, digest)
    if upgraded is None:
        store.pending_checked(job, _utc_text(now), _next_pending_attempt(job, now))
        return

    target_state = _target_state(upgraded, digest)
    write_proof_atomic(proof_path, upgraded, replace=True)
    if target_state == UPGRADED_UNVERIFIED:
        store.transition(job, target_state, _utc_text(now))
    else:
        store.pending_checked(job, _utc_text(now), _next_pending_attempt(job, now))


def _process_job(
    store: LifecycleStore,
    job: sqlite3.Row,
    backend: TimestampBackend,
    now: datetime,
    jitter_sample: float,
) -> None:
    if job["state"] == RETRY_FAILED:
        job = store.resume_retry(job)
    try:
        if job["state"] == QUEUED:
            _process_queued(store, job, backend, now)
        elif job["state"] == SUBMITTED_PENDING:
            _process_pending(store, job, backend, now)
    except AnchorConfigurationError:
        raise
    except AnchorIntegrityError as exc:
        store.record_failure(job, "integrity", str(exc), _utc_text(now), None)
        LOGGER.error(
            "anchor integrity failure for sequence %s: %s",
            job["sequence"],
            exc,
        )
    except Exception as exc:
        attempt = int(job["attempt_count"]) + 1
        delay = retry_delay_seconds(attempt, jitter_sample)
        failed = store.record_failure(
            job,
            "transient",
            str(exc),
            _utc_text(now),
            _utc_text(now + timedelta(seconds=delay)),
        )
        LOGGER.warning(
            "anchor transient failure for sequence %s; retry at %s: %s",
            job["sequence"],
            failed["next_attempt"],
            exc,
        )


def run_once(
    config: WorkerConfig,
    backend: TimestampBackend | None = None,
    *,
    now: datetime | None = None,
    jitter_sample: float | None = None,
) -> int:
    """Snapshot the current tip, process due lifecycle work, and exit."""
    current_time = now or datetime.now(UTC)
    sequence, tip_hash = snapshot_tip(config.chain_path)
    proof_path = config.proof_directory / f"{sequence}-{tip_hash}.ots"
    timestamp_backend = backend or OpenTimestampsBackend()

    with LifecycleStore(config.database_path) as store:
        store.track_tip(
            sequence,
            tip_hash,
            proof_path,
            config.interval_minutes,
            config.confirmation_threshold,
        )
        due_jobs = store.due_jobs(_utc_text(current_time))
        for job in due_jobs:
            sample = random.random() if jitter_sample is None else jitter_sample
            _process_job(store, job, timestamp_backend, current_time, sample)
        return len(due_jobs)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    chain_default = get_store_path()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", type=Path, default=chain_default)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--proof-directory", type=Path)
    parser.add_argument(
        "--interval-minutes",
        type=_positive_int,
        default=DEFAULT_INTERVAL_MINUTES,
    )
    parser.add_argument(
        "--confirmation-threshold",
        type=_positive_int,
        default=DEFAULT_CONFIRMATION_THRESHOLD,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    chain = args.chain.expanduser().resolve()
    config = WorkerConfig(
        chain_path=chain,
        database_path=(args.database or chain.parent / "anchors.sqlite3"),
        proof_directory=(args.proof_directory or chain.parent / "anchors"),
        interval_minutes=args.interval_minutes,
        confirmation_threshold=args.confirmation_threshold,
    )
    try:
        processed = run_once(config)
    except Exception:
        logging.exception("OpenTimestamps worker failed")
        return 1
    logging.info("OpenTimestamps worker processed %d job(s)", processed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
