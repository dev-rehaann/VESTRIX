"""Check every chain-format float vector against Python and Rust.

CI dependency: ``cargo`` and a Rust toolchain must be on PATH. ``cargo run``
builds the thin Rust example CLI before executing it.
"""

from __future__ import annotations

import difflib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from float_canonical import canonicalize_float

ROOT = Path(__file__).resolve().parents[1]
VECTORS_PATH = ROOT / "tests" / "vectors" / "float_canonicalization.json"
REJECTED = "<rejected>"


def _vectors() -> list[dict[str, object]]:
    document = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    if document.get("format_version") != 1:
        raise ValueError("unsupported or missing float-vector format_version")
    return [*document["valid_vectors"], *document["invalid_vectors"]]


def _python_lines(vectors: list[dict[str, object]]) -> list[str]:
    lines = []
    for vector in vectors:
        bits_hex = str(vector["binary64_hex"])
        value = struct.unpack(">d", bytes.fromhex(bits_hex))[0]
        try:
            rendered = canonicalize_float(value)
        except ValueError:
            rendered = REJECTED
        lines.append(f"{bits_hex}\t{rendered}")
    return lines


def _expected_lines(vectors: list[dict[str, object]]) -> list[str]:
    return [
        f"{vector['binary64_hex']}\t{vector['canonical'] or REJECTED}"
        for vector in vectors
    ]


def _rust_lines(vectors: list[dict[str, object]]) -> list[str]:
    toolchain = os.environ.get("VESTRIX_RUST_TOOLCHAIN")
    command = [
        "cargo",
        *([f"+{toolchain}"] if toolchain else []),
        "run",
        "--quiet",
        "--manifest-path",
        str(ROOT / "verifier-cli" / "Cargo.toml"),
        "--example",
        "canonicalize_float",
        "--",
        *(str(vector["binary64_hex"]) for vector in vectors),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("cargo is required for the cross-language check") from exc
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr)
        raise SystemExit(exc.returncode) from exc
    return result.stdout.splitlines()


def _diff(expected: list[str], actual: list[str], label: str) -> bool:
    if actual == expected:
        return True
    sys.stderr.writelines(
        difflib.unified_diff(
            [f"{line}\n" for line in expected],
            [f"{line}\n" for line in actual],
            fromfile="test-vectors",
            tofile=label,
        )
    )
    return False


def main() -> int:
    vectors = _vectors()
    expected = _expected_lines(vectors)
    python_lines = _python_lines(vectors)
    rust_lines = _rust_lines(vectors)
    passed = all(
        (
            _diff(expected, python_lines, "python"),
            _diff(expected, rust_lines, "rust"),
            _diff(python_lines, rust_lines, "python-vs-rust"),
        )
    )
    if not passed:
        return 1
    valid = sum(vector["canonical"] is not None for vector in vectors)
    print(
        "float canonicalization cross-language check passed: "
        f"{len(vectors)} vectors ({valid} canonical, {len(vectors) - valid} rejected)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
