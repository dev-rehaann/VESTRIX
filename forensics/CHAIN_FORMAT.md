# Vestrix forensic chain format, version 1

This document is the normative, byte-level specification for the first Vestrix
forensic chain format. A verifier does not need any Vestrix writer code to
implement it. There is no version field in version 1; deployments must associate
this specification with the chain out of band.

## Record schema

Every JSON record has exactly these fields and no others:

| Field | JSON type | Rule |
|---|---|---|
| `seq` | integer | Zero-based sequence, in `0..2^63-1` |
| `ts_utc` | string | RFC 3339 UTC timestamp in `YYYY-MM-DDTHH:MM:SS[.fraction]Z` form |
| `node_id` | string | Non-empty logger/node identifier |
| `raw_csi_hash` | string | 64 lowercase hexadecimal characters |
| `features_hash` | string | 64 lowercase hexadecimal characters |
| `model_id` | string | Non-empty model identifier |
| `model_config_hash` | string | 64 lowercase hexadecimal characters |
| `class` | string | Non-empty classification label |
| `confidence` | number | Finite number in the closed interval `[0,1]`; booleans are not numbers |
| `top_shap` | JSON value | JSON-compatible explanation data under the restrictions below |
| `prev_hash` | string | Previous record's `record_hash`, or the genesis sentinel |
| `record_hash` | string | SHA-256 digest specified below, as 64 lowercase hexadecimal characters |
| `signature` | string | Ed25519 signature specified below, as 128 lowercase hexadecimal characters |

All strings must contain Unicode scalar values; unpaired UTF-16 surrogate code
points are forbidden. `top_shap` can contain null, booleans, strings, arrays,
objects with string keys, signed 64-bit integers, and finite binary64 values.
NaN and positive/negative infinity are forbidden.

## Canonical JSON bytes

The normative serialization is defined by this section and the float rules
below. For permitted values, its reference Python 3.11 expression is:

```python
json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
```

Consequently:

1. Object keys are sorted lexicographically by Unicode code point.
2. There is no whitespace between tokens: commas and colons are exactly `,` and
   `:`.
3. Strings use JSON double quotes. Quote, reverse solidus, and control characters
   are escaped exactly as Python's `json.dumps`; non-ASCII scalar values are
   emitted directly and the result is encoded as UTF-8.
4. `true`, `false`, and `null` are lowercase.
5. Integers are base-10 with no leading zero. Binary64 values follow the
   normative Float Canonicalization Rules below. An implementation must not
   delegate this choice to an unspecified language-default formatter.

For the unsigned object described below, the resulting top-level key order is:

```text
class, confidence, features_hash, model_config_hash, model_id, node_id,
prev_hash, raw_csi_hash, seq, top_shap, ts_utc
```

For the complete stored object, the top-level key order is:

```text
class, confidence, features_hash, model_config_hash, model_id, node_id,
prev_hash, raw_csi_hash, record_hash, seq, signature, top_shap, ts_utc
```

## Float Canonicalization Rules

These rules are normative for every value represented as an IEEE 754 binary64,
including a float-typed `confidence` and binary64 values nested in `top_shap`.
The input to canonicalization is the 64-bit binary64 value, not its source-code
spelling.

1. Reject NaN, positive infinity, and negative infinity before hashing.
2. Render positive zero as `0.0` and negative zero as `-0.0`. The sign bit of
   zero is hash-significant.
3. For any other value, obtain the shortest correctly rounded decimal
   significand that parses back to exactly the same binary64 bits under IEEE
   754 round-to-nearest, ties-to-even. If equally short candidates exist, use
   the candidate closest to the exact binary64 value; an exact midpoint is
   resolved by an even final digit. Remove no digit needed for round-trip.
4. Let `k` be the adjusted base-10 exponent: the exponent when exactly one
   significant digit is placed before the decimal point.
5. If `-4 <= k < 16`, use fixed-point notation. Insert leading or trailing
   zeroes as required. Remove trailing fractional zeroes, but if the result has
   no fractional digits, append `.0` to preserve the binary64 type.
6. Otherwise use scientific notation with one digit before the decimal point.
   Include a decimal point only when more significant digits follow. Use a
   lowercase `e`, always include the exponent sign, and pad an exponent whose
   magnitude is below 10 to two digits. Do not truncate exponents with three or
   more digits.
7. Prefix `-` for negative values. Do not emit a leading `+`, locale-specific
   separators, whitespace, or uppercase exponent markers.

This is the shortest-round-trip rendering used by CPython 3.11's JSON encoder,
made explicit so independent implementations do not rely on their language's
default float-to-string thresholds. It preserves every binary64 value without
introducing a fixed rounding precision and, critically, preserves the existing
chain-format version 1 bytes.

### Worked examples

| Binary64 value | Canonical token | Reason |
|---|---|---|
| `1.0` | `1.0` | The value is float-typed, so the otherwise integral fixed-point result keeps `.0`. |
| `0.30000000000000004` | `0.30000000000000004` | Removing digits would round-trip to different binary64 bits. |
| `0.00001` (`1e-05`) | `1e-05` | Adjusted exponent `-5` selects scientific notation and the exponent is zero-padded. |

### Float canonicalization test vectors

The `binary64 hex` column is the normative input and removes ambiguity caused
by parsing decimal source text. The input label is explanatory. The versioned,
machine-readable copy is
[`CHAIN_FORMAT_TEST_VECTORS.json`](CHAIN_FORMAT_TEST_VECTORS.json).

| Input label | Binary64 hex | Canonical token | Divergence covered |
|---|---|---|---|
| `1.0` | `3ff0000000000000` | `1.0` | Float type marker on an integral value |
| `0.30000000000000004` | `3fd3333333333334` | `0.30000000000000004` | Required shortest-round-trip digits |
| `0.00001` | `3ee4f8b588e368f1` | `1e-05` | Fixed/scientific threshold and exponent padding |
| `0.0` | `0000000000000000` | `0.0` | Positive zero |
| `-0.0` | `8000000000000000` | `-0.0` | Negative-zero sign preservation |
| `5e-324` | `0000000000000001` | `5e-324` | Smallest positive subnormal |
| `2.225073858507201e-308` | `000fffffffffffff` | `2.225073858507201e-308` | Largest subnormal |
| `2.2250738585072014e-308` | `0010000000000000` | `2.2250738585072014e-308` | Smallest positive normal |
| `1.7976931348623157e308` | `7fefffffffffffff` | `1.7976931348623157e+308` | Largest finite value and three-digit exponent |
| decimal input `1.23456789012345678` | `3ff3c0ca428c59fb` | `1.2345678901234567` | Binary64 rounding and 17-digit boundary |
| `-0.125` | `bfc0000000000000` | `-0.125` | Exactly representable negative fraction |
| `42.0` | `4045000000000000` | `42.0` | Integer-looking binary64 |
| `0.0001` | `3f1a36e2eb1c432d` | `0.0001` | Fixed-point lower threshold at `k = -4` |
| `10000000000000000.0` | `4341c37937e08000` | `1e+16` | Scientific upper threshold at `k = 16` |
| `999999999999999.9` | `430c6bf52633ffff` | `999999999999999.9` | Large value below scientific threshold |
| `0.00000012` | `3e801b2b29a4692b` | `1.2e-07` | Lowercase `e` and negative exponent padding |
| `100000000000000000000.0` | `4415af1d78b58c40` | `1e+20` | Python/Rust default notation divergence |
| `-12345.6789` | `c0c81cd6e631f8a1` | `-12345.6789` | Negative fixed-point value |
| `9007199254740992.0` | `4340000000000000` | `9007199254740992.0` | Exact-integer precision boundary |
| NaN | `7ff8000000000000` | rejected | Non-finite value |
| positive infinity | `7ff0000000000000` | rejected | Non-finite value |
| negative infinity | `fff0000000000000` | rejected | Non-finite value |

### Integer-versus-float schema boundary

Chain format version 1 does not coerce JSON integers into binary64 values. The
JSON integer `1` canonicalizes as `1`; binary64 `1.0` canonicalizes as `1.0`,
and the two records hash differently. The current `confidence` schema says
`number`, so either representation can arrive from a producer. Producers must
therefore preserve and consistently choose the intended numeric type. Changing
this boundary would require a new chain-format version; it must not be guessed
or normalized by a version-1 verifier.

Reference implementations are
[`float_canonical.py`](float_canonical.py) and
[`canonical.rs`](../verifier-cli/src/canonical.rs). Run
[`check_float_canonicalization.py`](check_float_canonicalization.py) to compare
both implementations against every machine-readable vector.

## Hashing and signing procedure

For each event, perform these steps in order:

1. Set `seq` to zero for the first record; otherwise set it to the previous
   record's `seq + 1`.
2. Set genesis `prev_hash` to exactly 64 ASCII zero characters. Otherwise set it
   to the previous record's 64-character lowercase `record_hash`.
3. Construct the **unsigned object** from exactly the eleven fields `seq`,
   `ts_utc`, `node_id`, `raw_csi_hash`, `features_hash`, `model_id`,
   `model_config_hash`, `class`, `confidence`, `top_shap`, and `prev_hash`.
   Neither `record_hash` nor `signature` is present.
4. Canonically serialize the unsigned object. Call the resulting UTF-8 byte
   sequence `record_bytes`.
5. Compute `SHA-256(record_bytes)` and encode its 32 bytes as lowercase hex. This
   is `record_hash`.
6. Compute an Ed25519 signature over exactly `record_bytes`, using the logger's
   private key. Encode the 64 signature bytes as lowercase hex. This is
   `signature`. The digest hex is not signed separately; both digest and
   signature cover identical `record_bytes`.
7. Add `record_hash` and `signature`, canonically serialize the complete record,
   and append those bytes followed by exactly one LF byte (`0x0a`) to the store.
   LF is not part of `record_bytes` and is not hashed or signed. CRLF, blank
   lines, a missing final LF, a UTF-8 BOM, and non-canonical stored JSON are
   invalid.

### Minimal genesis shape

The exact `record_bytes` depend on event values, but every genesis unsigned
object includes:

```json
"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":0
```

in the canonical positions shown above.

## Verification algorithm

A verifier starts with `expected_seq = 0` and `expected_prev_hash = "0" * 64`,
then processes physical lines from the beginning:

1. Require an LF-terminated, non-empty line. Remove only that final LF.
2. Decode strict UTF-8 and parse one JSON object. Require the exact schema and
   value constraints above.
3. Canonically serialize the complete parsed object and require byte-for-byte
   equality with the stored line. This detects otherwise-ignorable whitespace,
   escape, key-order, or duplicate-key alterations.
4. Require `seq == expected_seq` and `prev_hash == expected_prev_hash`.
5. Remove `record_hash` and `signature`, canonically serialize the remaining
   object, SHA-256 it, and require lowercase digest equality with `record_hash`.
6. Decode `signature` from lowercase hex and verify Ed25519 over those same
   canonical unsigned bytes using the known, out-of-band public key.
7. Set `expected_seq += 1` and `expected_prev_hash = record_hash`.

The chain is valid only if every step succeeds for every line. An empty existing
file is structurally valid but has no chain tip and cannot be timestamp-anchored.
Signature verification authenticates records to the holder of the private key;
OpenTimestamps anchoring separately establishes that a selected tip existed no
later than an independently verifiable time.

## Interoperability test vector

This genesis vector uses an Ed25519 test key. Its raw 32-byte public key is:

```text
03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
```

The exact UTF-8 `record_bytes` (shown as text, with no trailing LF) are:

```json
{"class":"normal","confidence":0.875,"features_hash":"2222222222222222222222222222222222222222222222222222222222222222","model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","seq":0,"top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}
```

Expected lowercase SHA-256:

```text
ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8
```

Expected lowercase Ed25519 signature:

```text
872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f
```

The exact stored line is the following bytes plus one final `0x0a`:

```json
{"class":"normal","confidence":0.875,"features_hash":"2222222222222222222222222222222222222222222222222222222222222222","model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","record_hash":"ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8","seq":0,"signature":"872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f","top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}
```

### Binary64 hash/signature regression vectors

These signed-record regressions prove that selected canonical float tokens feed
the existing hash and signature procedure unchanged. They use the same unsigned
genesis object and test key as the primary vector above. The test private-key
seed is the 32 bytes
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.
For each row, the exact `record_bytes` are the primary vector's `record_bytes`
with only the ASCII token after `"confidence":` replaced by the listed token.
No other byte changes.

| Python source value | Canonical confidence token | Expected SHA-256 | Expected Ed25519 signature |
|---|---|---|---|
| `1.0` | `1.0` | `427c3016848a90a8d4219a137b486fef785361379e5fbf1864451be59b4e67a0` | `1587c4fe5d1499e72b931e8989d481b6d071e56506798e4f0bf9f3df60497d35ae95d5b8bb6caa963c7ed285430ef021eb103a3b7675b08dbb9a271f7924480b` |
| `0.9532` | `0.9532` | `db55f077ce463a4ff1015aba74eadd3c5fd6ed31d78f0b77587c7b464f7872ed` | `e8eadc6abfdd5cb34d2c5445a0083dbcd44bfb5e6cd11814d9a9ca814b0b7fbd1b20d0368b7b57b51565eb620c0f5dd531c6f689ffff791f5ec3457fddd0340b` |
| `0.1 + 0.2` | `0.30000000000000004` | `3aa30e8f2ae3dbf23a617238837d97363be4aef9c9ff99a44d4c5ac44ca233d1` | `e1b7ac82d66bfe177c1ba65a77b21ffde25e9e31d0d13075711df1256a85e940bfcb62ee7602dda55ab0b58c2e532c9537188dc8f168a7d20cdbecbc08926001` |
| `0.00001` | `1e-05` | `10869621de6d71b59d6a112924e22ae7c152b3247e87695730300ba0bd7c8d27` | `5c84aee62bd7bcf98dfe7e9c11bbdafd214869f8e142f6cd340910a67674d8a7cc1f1691d8b11c09d2d6a9ecfc185300fc0e5f2c6904e2e3f0c346e180b3a808` |

The complete scalar vector set appears in Float Canonicalization Rules above.
Negative finite binary64 values are valid inside `top_shap` even though values
below zero are invalid for `confidence`.
