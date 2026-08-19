"""Reference binary64 canonicalization for Vestrix chain format version 1."""

from __future__ import annotations

import json
import math


def canonicalize_float(value: float) -> str:
    """Implement CHAIN_FORMAT.md ``Float Canonicalization`` for binary64."""
    if not isinstance(value, float):
        raise TypeError("value must be a binary64 float")
    if not math.isfinite(value):
        raise ValueError("NaN and infinity are not permitted")
    return json.dumps(value, allow_nan=False, separators=(",", ":"))
