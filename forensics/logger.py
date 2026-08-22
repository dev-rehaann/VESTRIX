"""Append-only, hash-chained forensic event writer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol

from filelock import FileLock

from ._format import (
    canonical_json_bytes,
    hash_unsigned_record,
    record_format_version,
    validate_event,
)
from ._store import StoreError, chain_tip

STORE_PATH_ENV = "VESTRIX_FORENSICS_STORE"
DEFAULT_STORE_PATH = Path(__file__).resolve().parent / "store" / "chain.jsonl"
LOCK_TIMEOUT_SECONDS = 30.0


class Signer(Protocol):
    """The minimal signing capability required by :func:`log_event`."""

    def sign(self, data: bytes) -> bytes:
        """Return a 64-byte Ed25519 signature over ``data``."""
        ...


class AppendError(RuntimeError):
    """Raised when a record cannot safely be appended."""


def get_store_path() -> Path:
    """Return the configured chain path (primarily overridable for deployment/tests)."""
    configured = os.environ.get(STORE_PATH_ENV)
    return Path(configured).expanduser().resolve() if configured else DEFAULT_STORE_PATH


def lock_path_for(store_path: Path) -> Path:
    """Return the sidecar lock path shared by writers, verifiers, and anchor reads."""
    return store_path.with_name(f"{store_path.name}.lock")


def log_event(event: dict[str, Any], signer: Signer) -> dict[str, Any]:
    """Validate, hash, sign, durably append, and return one forensic record.

    A process-wide and cross-process sidecar file lock covers validation of the
    existing chain, sequence allocation, and append. This avoids duplicate
    sequence numbers and lost updates when multiple workers share a local store.
    """
    event_fields = validate_event(event)
    store_path = get_store_path()
    store_path.parent.mkdir(parents=True, exist_ok=True)
    lock = FileLock(str(lock_path_for(store_path)), timeout=LOCK_TIMEOUT_SECONDS)

    with lock:
        try:
            seq, previous_hash = chain_tip(
                store_path, record_format_version(event_fields)
            )
        except StoreError as exc:
            raise AppendError(f"refusing to append to an invalid chain: {exc}") from exc

        unsigned_record: dict[str, Any] = {
            **event_fields,
            "seq": seq,
            "prev_hash": previous_hash,
        }
        record_bytes, record_hash = hash_unsigned_record(unsigned_record)
        signature = signer.sign(record_bytes)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise AppendError("signer must return a 64-byte Ed25519 signature")

        record = {
            **unsigned_record,
            "record_hash": record_hash,
            "signature": signature.hex(),
        }
        encoded_line = canonical_json_bytes(record) + b"\n"
        try:
            with store_path.open("ab") as store:
                store.write(encoded_line)
                store.flush()
                os.fsync(store.fileno())
        except OSError as exc:
            message = f"failed to durably append forensic record: {exc}"
            raise AppendError(message) from exc

    return record
