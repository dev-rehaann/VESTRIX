"""Strict JSONL storage parsing used inside an already-acquired file lock."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ._format import (
    GENESIS_PREV_HASH,
    RecordFormatError,
    canonical_json_bytes,
    hash_unsigned_record,
    record_format_version,
    validate_stored_record,
)


class StoreError(ValueError):
    """A chain store is malformed or internally inconsistent."""

    def __init__(self, line_number: int, reason: str) -> None:
        self.line_number = line_number
        self.reason = reason
        super().__init__(f"line {line_number}: {reason}")


def iter_validated_records(path: Path) -> Iterator[tuple[int, dict[str, Any], bytes]]:
    """Yield structurally and cryptographically linked records from ``path``."""
    expected_seq = 0
    expected_prev_hash = GENESIS_PREV_HASH
    expected_format_version: int | None = None

    try:
        store = path.open("rb")
    except FileNotFoundError:
        return

    with store:
        for line_number, physical_line in enumerate(store, start=1):
            if not physical_line.endswith(b"\n"):
                raise StoreError(line_number, "record is not terminated by LF")
            line = physical_line[:-1]
            if not line:
                raise StoreError(line_number, "blank lines are forbidden")
            try:
                parsed = json.loads(line)
                record = validate_stored_record(parsed)
            except (json.JSONDecodeError, UnicodeDecodeError, RecordFormatError) as exc:
                raise StoreError(line_number, f"invalid record: {exc}") from exc

            format_version = record_format_version(record)
            if expected_format_version is None:
                expected_format_version = format_version
            elif format_version != expected_format_version:
                raise StoreError(line_number, "chain mixes format versions")

            if canonical_json_bytes(record) != line:
                raise StoreError(line_number, "stored JSON is not in canonical form")
            if record["seq"] != expected_seq:
                raise StoreError(
                    line_number,
                    f"expected seq {expected_seq}, found {record['seq']}",
                )
            if record["prev_hash"] != expected_prev_hash:
                raise StoreError(
                    line_number,
                    "prev_hash does not match the previous record",
                )

            signed_bytes, expected_record_hash = hash_unsigned_record(record)
            if record["record_hash"] != expected_record_hash:
                raise StoreError(
                    line_number,
                    "record_hash does not match record content",
                )

            yield line_number, record, signed_bytes
            expected_seq += 1
            expected_prev_hash = record["record_hash"]


def chain_tip(
    path: Path, required_format_version: int | None = None
) -> tuple[int, str]:
    """Return the next sequence and preceding hash after validating the store."""
    next_seq = 0
    previous_hash = GENESIS_PREV_HASH
    for line_number, record, _ in iter_validated_records(path):
        if (
            required_format_version is not None
            and record_format_version(record) != required_format_version
        ):
            raise StoreError(line_number, "cannot append a different format version")
        next_seq = record["seq"] + 1
        previous_hash = record["record_hash"]
    return next_seq, previous_hash
