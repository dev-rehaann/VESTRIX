"""Canonical record-format primitives shared by the writer and verifier."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

GENESIS_PREV_HASH = "0" * 64
V1_EVENT_FIELDS = frozenset(
    {
        "ts_utc",
        "node_id",
        "raw_csi_hash",
        "features_hash",
        "model_id",
        "model_config_hash",
        "class",
        "confidence",
        "top_shap",
    }
)
V2_COMMON_EVENT_FIELDS = frozenset(
    {"format_version", "event_type", "ts_utc", "node_id", "raw_csi_hash"}
)
V2_INGESTION_EVENT_FIELDS = V2_COMMON_EVENT_FIELDS | {
    "collector_schema_version",
    "collector_sequence_number",
}
V2_CLASSIFICATION_EVENT_FIELDS = V2_COMMON_EVENT_FIELDS | {
    "features_hash",
    "model_id",
    "model_config_hash",
    "class",
    "confidence",
    "top_shap",
}
MANAGED_FIELDS = frozenset({"seq", "prev_hash", "record_hash", "signature"})

_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_RFC3339_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


class RecordFormatError(ValueError):
    """Raised when an event or stored record violates the chain format."""


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize a mapping using the normative Vestrix JSON encoding."""
    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        message = f"value is not canonical-JSON encodable: {exc}"
        raise RecordFormatError(message) from exc
    try:
        return serialized.encode("utf-8")
    except UnicodeEncodeError as exc:
        message = "strings must contain only Unicode scalar values"
        raise RecordFormatError(message) from exc


def hash_unsigned_record(record: Mapping[str, Any]) -> tuple[bytes, str]:
    """Return the signed bytes and lowercase SHA-256 digest for a record."""
    unsigned = {
        key: value
        for key, value in record.items()
        if key not in {"record_hash", "signature"}
    }
    record_bytes = canonical_json_bytes(unsigned)
    return record_bytes, hashlib.sha256(record_bytes).hexdigest()


def validate_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy the caller-controlled portion of a record."""
    if not isinstance(event, Mapping):
        raise RecordFormatError("event must be a mapping")
    if not all(isinstance(key, str) for key in event):
        raise RecordFormatError("event keys must be strings")

    keys = set(event)
    expected = _event_fields(event)
    missing = expected - keys
    unknown = keys - expected
    if missing:
        raise RecordFormatError(f"event is missing fields: {sorted(missing)}")
    if unknown:
        message = f"event has unknown or managed fields: {sorted(unknown)}"
        raise RecordFormatError(message)

    copied = dict(event)
    _validate_event_values(copied)
    return copied


def validate_stored_record(record: object) -> dict[str, Any]:
    """Validate a parsed, complete record and return it with a precise type."""
    if not isinstance(record, dict):
        raise RecordFormatError("record must be a JSON object")
    if not all(isinstance(key, str) for key in record):
        raise RecordFormatError("record keys must be strings")

    missing_managed = MANAGED_FIELDS - set(record)
    if missing_managed:
        raise RecordFormatError(
            f"record is missing fields: {sorted(missing_managed)}"
        )
    event = {key: value for key, value in record.items() if key not in MANAGED_FIELDS}
    validate_event(event)
    seq = record["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < 2**63:
        raise RecordFormatError("seq must be an integer between 0 and 2^63-1")
    _require_hash(record["prev_hash"], "prev_hash")
    _require_hash(record["record_hash"], "record_hash")

    signature = record["signature"]
    if not isinstance(signature, str) or len(signature) != 128:
        raise RecordFormatError(
            "signature must be 128 lowercase hexadecimal characters"
        )
    if any(char not in "0123456789abcdef" for char in signature):
        raise RecordFormatError(
            "signature must be 128 lowercase hexadecimal characters"
        )
    return record


def _validate_event_values(event: Mapping[str, Any]) -> None:
    _event_fields(event)
    _require_nonempty_string(event["node_id"], "node_id")

    timestamp = event["ts_utc"]
    if not isinstance(timestamp, str) or _RFC3339_UTC_RE.fullmatch(timestamp) is None:
        raise RecordFormatError("ts_utc must be an RFC 3339 UTC string ending in 'Z'")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as exc:
        raise RecordFormatError("ts_utc must be a valid RFC 3339 timestamp") from exc
    if parsed_timestamp.utcoffset() != UTC.utcoffset(parsed_timestamp):
        raise RecordFormatError("ts_utc must represent UTC")

    _require_hash(event["raw_csi_hash"], "raw_csi_hash")

    if (
        record_format_version(event) == 1
        or event["event_type"] == "classification_decision"
    ):
        for field in ("model_id", "class"):
            _require_nonempty_string(event[field], field)
        for field in ("features_hash", "model_config_hash"):
            _require_hash(event[field], field)

        confidence = event["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise RecordFormatError("confidence must be a JSON number")
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise RecordFormatError("confidence must be finite and between 0 and 1")

        _validate_json_value(event["top_shap"], "top_shap")
        return

    _require_nonempty_string(
        event["collector_schema_version"], "collector_schema_version"
    )
    sequence = event["collector_sequence_number"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 0 <= sequence < 2**63
    ):
        raise RecordFormatError(
            "collector_sequence_number must be an integer between 0 and 2^63-1"
        )


def record_format_version(record: Mapping[str, Any]) -> int:
    """Return the validated chain-format version for an event or record."""
    return 2 if record.get("format_version") == 2 else 1


def _event_fields(event: Mapping[str, Any]) -> frozenset[str]:
    if "format_version" not in event:
        if "event_type" in event:
            raise RecordFormatError("version 2 event is missing format_version")
        return V1_EVENT_FIELDS

    version = event["format_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 2:
        raise RecordFormatError("format_version must be integer 2")
    event_type = event.get("event_type")
    if event_type == "ingestion_accepted":
        return V2_INGESTION_EVENT_FIELDS
    if event_type == "classification_decision":
        return V2_CLASSIFICATION_EVENT_FIELDS
    raise RecordFormatError(
        "event_type must be 'ingestion_accepted' or 'classification_decision'"
    )


def _require_nonempty_string(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise RecordFormatError(f"{field} must be a non-empty string")
    _require_unicode_scalars(value, field)


def _require_hash(value: object, field: str) -> None:
    if not isinstance(value, str) or _HEX_64_RE.fullmatch(value) is None:
        raise RecordFormatError(f"{field} must be 64 lowercase hexadecimal characters")


def _validate_json_value(value: object, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _require_unicode_scalars(value, path)
        return
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            message = f"{path} integer is outside the signed 64-bit range"
            raise RecordFormatError(message)
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RecordFormatError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RecordFormatError(f"{path} contains a non-string object key")
            _require_unicode_scalars(key, f"{path} object key")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise RecordFormatError(f"{path} contains unsupported type {type(value).__name__}")


def _require_unicode_scalars(value: str, path: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise RecordFormatError(f"{path} contains a Unicode surrogate")
