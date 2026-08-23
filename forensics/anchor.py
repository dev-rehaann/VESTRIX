"""Interface for periodically anchoring a chain tip with OpenTimestamps."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from filelock import FileLock
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

from ._store import chain_tip
from .logger import LOCK_TIMEOUT_SECONDS, lock_path_for


class TimestampBackend(Protocol):
    """Backend boundary; only implementations of this method may use the network."""

    def stamp(self, digest: bytes) -> bytes:
        """Submit a 32-byte digest and return a serialized timestamp proof."""
        ...

    def upgrade(self, proof: bytes, digest: bytes) -> bytes | None:
        """Return an upgraded proof, or ``None`` while it remains pending."""
        ...


class AnchorIntegrityError(ValueError):
    """A proof is malformed or does not bind to its expected chain tip."""


class AnchorTransientError(RuntimeError):
    """A calendar/client operation failed and may succeed on a later run."""


class AnchorConfigurationError(ValueError):
    """The pinned OpenTimestamps client was configured inconsistently."""


@dataclass(frozen=True, slots=True)
class AnchorReceipt:
    """Metadata for a proof written for one immutable chain tip."""

    sequence: int
    tip_hash: str
    proof_path: Path


@dataclass(frozen=True, slots=True)
class ProofInspection:
    """Security-relevant facts extracted from one detached proof."""

    digest: bytes
    has_bitcoin_attestation: bool


Submitter = Callable[[Timestamp], None]
Upgrader = Callable[[Timestamp], bool]
NonceFactory = Callable[[int], bytes]


class OpenTimestampsBackend:
    """Pinned OpenTimestamps client adapter for digest-bound detached proofs."""

    def __init__(
        self,
        submitter: Submitter | None = None,
        upgrader: Upgrader | None = None,
        nonce_factory: NonceFactory = os.urandom,
    ) -> None:
        self._submitter = submitter or _submit_with_client_defaults
        self._upgrader = upgrader or _upgrade_with_client_defaults
        self._nonce_factory = nonce_factory

    def stamp(self, digest: bytes) -> bytes:
        """Submit ``digest`` without hashing it a second time."""
        if len(digest) != 32:
            raise ValueError("OpenTimestamps input must be a 32-byte digest")

        detached = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
        nonce = self._nonce_factory(16)
        if not isinstance(nonce, bytes) or len(nonce) != 16:
            raise ValueError("OpenTimestamps nonce factory must return 16 bytes")
        calendar_commitment = detached.timestamp.ops.add(OpAppend(nonce)).ops.add(
            OpSHA256()
        )
        try:
            self._submitter(calendar_commitment)
        except AnchorConfigurationError:
            raise
        except AnchorTransientError:
            raise
        except SystemExit as exc:
            raise AnchorTransientError("OpenTimestamps calendar quorum failed") from exc
        except Exception as exc:
            raise AnchorTransientError(
                f"OpenTimestamps submission failed: {exc}"
            ) from exc
        return _serialize_detached(detached)

    def upgrade(self, proof: bytes, digest: bytes) -> bytes | None:
        """Ask calendars to upgrade a valid pending proof."""
        detached = _validated_detached(proof, digest)
        try:
            changed = self._upgrader(detached.timestamp)
        except AnchorTransientError:
            raise
        except SystemExit as exc:
            raise AnchorTransientError("OpenTimestamps upgrade failed") from exc
        except Exception as exc:
            raise AnchorTransientError(f"OpenTimestamps upgrade failed: {exc}") from exc
        return _serialize_detached(detached) if changed else None


def _submit_with_client_defaults(timestamp: Timestamp) -> None:
    """Use the pinned client's own calendar, timeout, and quorum defaults."""
    try:
        from opentimestamps.calendar import DEFAULT_AGGREGATORS
        from otsclient.args import parse_ots_args
        from otsclient.cmds import create_timestamp

        args = parse_ots_args(["stamp"])
        calendar_urls = list(DEFAULT_AGGREGATORS)
        if not 0 < args.m <= len(calendar_urls):
            raise AnchorConfigurationError(
                f"OpenTimestamps quorum {args.m} is invalid for "
                f"{len(calendar_urls)} calendars"
            )
        create_timestamp(timestamp, calendar_urls, args)
    except AnchorConfigurationError:
        raise
    except AnchorTransientError:
        raise
    except SystemExit as exc:
        raise AnchorTransientError("OpenTimestamps calendar quorum failed") from exc
    except Exception as exc:
        raise AnchorTransientError(f"OpenTimestamps client unavailable: {exc}") from exc


def _upgrade_with_client_defaults(timestamp: Timestamp) -> bool:
    """Query pending attestations without hiding transient calendar failures."""
    try:
        import otsclient
        from opentimestamps.calendar import (
            DEFAULT_CALENDAR_WHITELIST,
            CommitmentNotFoundError,
            RemoteCalendar,
        )

        changed = False
        failures: list[str] = []
        for pending_timestamp in _directly_attested_timestamps(timestamp):
            for attestation in tuple(pending_timestamp.attestations):
                if not isinstance(attestation, PendingAttestation):
                    continue
                if attestation.uri not in DEFAULT_CALENDAR_WHITELIST:
                    continue
                calendar = RemoteCalendar(
                    attestation.uri,
                    user_agent=f"OpenTimestamps-Client/{otsclient.__version__}",
                )
                before = set(timestamp.all_attestations())
                try:
                    upgraded = calendar.get_timestamp(pending_timestamp.msg)
                except CommitmentNotFoundError:
                    continue
                except Exception as exc:
                    failures.append(f"{attestation.uri}: {exc}")
                    continue
                pending_timestamp.merge(upgraded)
                changed = changed or set(timestamp.all_attestations()) != before
        if failures:
            raise AnchorTransientError("; ".join(failures))
        return changed
    except AnchorTransientError:
        raise
    except SystemExit as exc:
        raise AnchorTransientError("OpenTimestamps upgrade failed") from exc
    except Exception as exc:
        raise AnchorTransientError(f"OpenTimestamps client unavailable: {exc}") from exc


def _directly_attested_timestamps(timestamp: Timestamp) -> list[Timestamp]:
    if timestamp.attestations:
        return [timestamp]
    return [
        descendant
        for child in timestamp.ops.values()
        for descendant in _directly_attested_timestamps(child)
    ]


def _serialize_detached(detached: DetachedTimestampFile) -> bytes:
    context = BytesSerializationContext()
    detached.serialize(context)
    return context.getbytes()


def _validated_detached(proof: bytes, expected_digest: bytes) -> DetachedTimestampFile:
    if not isinstance(proof, bytes) or not proof:
        raise AnchorIntegrityError("proof must be non-empty bytes")
    if len(expected_digest) != 32:
        raise AnchorIntegrityError("expected digest must contain exactly 32 bytes")
    try:
        context = BytesDeserializationContext(proof)
        detached = DetachedTimestampFile.deserialize(context)
        context.assert_eof()
    except Exception as exc:
        raise AnchorIntegrityError(f"malformed OpenTimestamps proof: {exc}") from exc
    if not isinstance(detached.file_hash_op, OpSHA256):
        raise AnchorIntegrityError("OpenTimestamps proof file hash is not SHA-256")
    if detached.file_digest != expected_digest:
        raise AnchorIntegrityError(
            "OpenTimestamps proof digest does not match chain tip"
        )
    return detached


def inspect_proof(proof: bytes, expected_digest: bytes) -> ProofInspection:
    """Validate proof framing and digest binding, then classify its attestations."""
    detached = _validated_detached(proof, expected_digest)
    has_bitcoin_attestation = any(
        isinstance(attestation, BitcoinBlockHeaderAttestation)
        for _, attestation in detached.timestamp.all_attestations()
    )
    return ProofInspection(detached.file_digest, has_bitcoin_attestation)


def write_proof_atomic(target: Path, proof: bytes, *, replace: bool) -> None:
    """Durably publish complete proof bytes at ``target``."""
    if not isinstance(proof, bytes) or not proof:
        raise ValueError("timestamp backend returned an empty or non-bytes proof")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not replace and target.exists():
        raise FileExistsError(target)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as proof_file:
            proof_file.write(proof)
            proof_file.flush()
            os.fsync(proof_file.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def anchor_chain_tip(
    store_path: str | Path,
    proof_path: str | Path,
    backend: TimestampBackend,
) -> AnchorReceipt:
    """Snapshot the current tip, timestamp it, and durably save the returned proof."""
    store = Path(store_path).expanduser().resolve()
    target = Path(proof_path).expanduser().resolve()
    if not store.exists():
        raise FileNotFoundError(store)

    lock = FileLock(str(lock_path_for(store)), timeout=LOCK_TIMEOUT_SECONDS)
    with lock:
        next_seq, tip_hash = chain_tip(store)
    if next_seq == 0:
        raise ValueError("cannot anchor an empty chain")

    proof = backend.stamp(bytes.fromhex(tip_hash))
    if not isinstance(proof, bytes) or not proof:
        raise ValueError("timestamp backend returned an empty or non-bytes proof")

    write_proof_atomic(target, proof, replace=False)
    return AnchorReceipt(sequence=next_seq - 1, tip_hash=tip_hash, proof_path=target)
