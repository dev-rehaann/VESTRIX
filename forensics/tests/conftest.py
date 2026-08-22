from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def event_factory() -> Callable[[int], dict[str, Any]]:
    def make_event(index: int) -> dict[str, Any]:
        def digest(label: str) -> str:
            return hashlib.sha256(f"{label}-{index}".encode()).hexdigest()

        return {
            "format_version": 2,
            "event_type": "classification_decision",
            "ts_utc": f"2026-07-13T12:00:{index % 60:02d}Z",
            "node_id": f"node-{index % 3}",
            "raw_csi_hash": digest("raw"),
            "features_hash": digest("features"),
            "model_id": "rf-test-v1",
            "model_config_hash": digest("config"),
            "class": "intrusion" if index % 2 else "normal",
            "confidence": 0.75 + (index % 10) / 100,
            "top_shap": [
                {"feature": "variance", "rank": 1, "value": index / 100},
                {"feature": "amplitude", "rank": 2, "value": -0.125},
            ],
        }

    return make_event
