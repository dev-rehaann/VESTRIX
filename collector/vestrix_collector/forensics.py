"""Collector adapter for the signed forensic event logger."""

from __future__ import annotations

import hashlib
import os

from forensics import log_event as append_forensic_event
from forensics.keys import load_private_key

from .models import CSIEvent

SIGNING_KEY_PATH_ENV = "VESTRIX_FORENSICS_PRIVATE_KEY"
_EMPTY_CONTENT_HASH = hashlib.sha256(b"").hexdigest()
_PROFILE_HASH = hashlib.sha256(b"vestrix-collector-accepted-event-v1").hexdigest()


def log_event(event: CSIEvent) -> None:
    """Durably append one authenticated collector event to the forensic chain."""
    key_path = os.environ.get(SIGNING_KEY_PATH_ENV)
    if not key_path:
        raise RuntimeError(f"{SIGNING_KEY_PATH_ENV} is not configured")

    append_forensic_event(
        {
            "ts_utc": event["timestamp_utc"],
            "node_id": event["node_id"],
            "raw_csi_hash": event["csi_window_sha256"],
            "features_hash": _EMPTY_CONTENT_HASH,
            "model_id": "vestrix-collector-adapter-v1",
            "model_config_hash": _PROFILE_HASH,
            "class": "collector_event_accepted",
            "confidence": 1.0,
            "top_shap": {
                "collector_schema_version": event["schema_version"],
                "collector_sequence_number": event["sequence_number"],
            },
        },
        load_private_key(key_path),
    )
