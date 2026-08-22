# Vestrix forensic chain format, version 2

This document is the normative, byte-level specification for Vestrix forensic
chain format version 2. A verifier does not need any Vestrix writer code to
implement it. Version 2 adds an in-record `format_version` and an `event_type`
discriminator so transport acceptance cannot be mistaken for an ML decision.

Version 1 remains defined by repository revisions before this version-2 change.
It has no version field and requires all six ML-specific fields in every record.
Current verifiers accept an unmixed legacy version-1 chain, but one chain must not
mix version-1 and version-2 records. A deployment upgrading from version 1 must
close the old chain segment and start a new version-2 store; the writer rejects an
attempt to append version 2 to an existing version-1 chain.

## Record schema

Every version-2 JSON record has exactly one of the two schemas below. Fields that
do not apply to an event type are absent, not null or filled with sentinels.

### Common event fields

| Field | JSON type | Rule |
|---|---|---|
| `format_version` | integer | Exactly `2` |
| `event_type` | string | Exactly `ingestion_accepted` or `classification_decision` |
| `ts_utc` | string | RFC 3339 UTC timestamp in `YYYY-MM-DDTHH:MM:SS[.fraction]Z` form |
| `node_id` | string | Non-empty logger/node identifier |
| `raw_csi_hash` | string | 64 lowercase hexadecimal characters |

### `ingestion_accepted` event fields

These fields are required in addition to the common fields:

| Field | JSON type | Rule |
|---|---|---|
| `collector_schema_version` | string | Non-empty collector payload-schema version |
| `collector_sequence_number` | integer | Collector anti-replay sequence in `0..2^63-1` |

The ML-specific fields below are forbidden on `ingestion_accepted` records.

### `classification_decision` event fields

These fields are required in addition to the common fields:

| Field | JSON type | Rule |
|---|---|---|
| `features_hash` | string | 64 lowercase hexadecimal characters |
| `model_id` | string | Non-empty model identifier |
| `model_config_hash` | string | 64 lowercase hexadecimal characters |
| `class` | string | Non-empty classification label |
| `confidence` | number | Finite number in the closed interval `[0,1]`; booleans are not numbers |
| `top_shap` | JSON value | JSON-compatible explanation data under the restrictions below |

### Managed chain fields

Every record of either event type also contains:

| Field | JSON type | Rule |
|---|---|---|
| `seq` | integer | Zero-based forensic-chain sequence, in `0..2^63-1` |
| `prev_hash` | string | Previous record's `record_hash`, or the genesis sentinel |
| `record_hash` | string | SHA-256 digest specified below, as 64 lowercase hexadecimal characters |
| `signature` | string | Ed25519 signature specified below, as 128 lowercase hexadecimal characters |

For example, the caller-controlled portion of an accepted collector event is:

```json
{
  "format_version": 2,
  "event_type": "ingestion_accepted",
  "ts_utc": "2026-07-13T12:00:00Z",
  "node_id": "node-01",
  "raw_csi_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "collector_schema_version": "0.1",
  "collector_sequence_number": 42
}
```

It contains no `features_hash`, `model_id`, `model_config_hash`, `class`,
`confidence`, or `top_shap` because no classification has occurred.

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
   normative Float Canonicalization section below. An implementation must not
   delegate this choice to an unspecified language-default formatter.

For an unsigned `ingestion_accepted` object, the resulting top-level key order is:

```text
collector_schema_version, collector_sequence_number, event_type, format_version,
node_id, prev_hash, raw_csi_hash, seq, ts_utc
```

For a complete `ingestion_accepted` object:

```text
collector_schema_version, collector_sequence_number, event_type, format_version,
node_id, prev_hash, raw_csi_hash, record_hash, seq, signature, ts_utc
```

For an unsigned `classification_decision` object:

```text
class, confidence, event_type, features_hash, format_version, model_config_hash,
model_id, node_id, prev_hash, raw_csi_hash, seq, top_shap, ts_utc
```

For a complete `classification_decision` object:

```text
class, confidence, event_type, features_hash, format_version, model_config_hash,
model_id, node_id, prev_hash, raw_csi_hash, record_hash, seq, signature,
top_shap, ts_utc
```

## Float Canonicalization

This section is normative for every value represented as an IEEE 754 binary64,
including `classification_decision.confidence` and binary64 values nested in its
`top_shap`.
The canonicalizer receives the 64-bit binary64 value, not its source-code
spelling or an independently recomputed mathematical value.

### Chosen representation and tradeoffs

Chain format version 2 retains version 1's **shortest round-trippable decimal JSON numbers**
(option (a)). The goal is the same as RFC 8785/JCS: one deterministic,
human-readable decimal token that recovers the identical binary64 value. The
fixed/scientific thresholds below deliberately retain the established CPython
3.11 JSON spelling, however, so this format is not byte-compatible with JCS at
every exponent.

Encoding the raw binary64 bits as 16 hexadecimal digits (option (c)) gives a
simpler bit-level guarantee, but it changes a JSON number into a string or a
new tagged structure. Applying it to version 1 would therefore change the
schema, historical `record_bytes`, hashes, and signatures. Fixed precision
(option (b)) is rejected because it either loses information or requires an
application-specific scale that does not fit both CSI features and SHAP values.

> **Maintainer sign-off required:** version 2 retains option (a). If hexadecimal
> binary64 is preferred, it must be introduced as a later chain-format version;
> it cannot be substituted into version 1 or version 2.

### Canonical form

1. Reject NaN, positive infinity, and negative infinity as validation errors
   before hashing. They have no canonical token.
2. Render positive zero as `0.0` and negative zero as `-0.0`. The zero sign bit
   is preserved because normalization would discard recorded input state and
   would change version-1 bytes.
3. For any other value, obtain the shortest correctly rounded decimal
   significand that parses back to exactly the same binary64 bits under IEEE
   754 round-to-nearest, ties-to-even. If equally short candidates exist, use
   the candidate closest to the exact binary64 value; resolve an exact midpoint
   with an even final digit. Remove no digit required for round-trip.
4. Let `k` be the adjusted base-10 exponent: the exponent when exactly one
   significant digit is placed before the decimal point.
5. If `-4 <= k < 16`, use fixed-point notation. Insert leading or trailing
   zeroes as required. Remove trailing fractional zeroes, but append `.0` when
   no fractional digits remain so a binary64 stays distinct from a JSON integer.
6. Otherwise use scientific notation with one digit before the decimal point.
   Include a decimal point only when more significant digits follow. Use a
   lowercase `e`, always include the exponent sign, and pad an exponent whose
   magnitude is below 10 to two digits. Do not truncate exponents with three or
   more digits.
7. Prefix `-` for negative values. Do not emit a leading `+`, locale-specific
   separators, whitespace, or an uppercase exponent marker.

Finite subnormal values use the same algorithm and round-trip to the identical
binary64 bits, including the smallest positive subnormal. No flush-to-zero is
permitted.

### Precision and rounding boundaries

The binary64 bits are authoritative. Decimal source text is rounded to binary64
once, before canonicalization; the canonicalizer performs no quantization or
application-level rounding. Thus the binary64 result of `0.1 + 0.2` is emitted
as `0.30000000000000004`, and decimal input `2.675` is emitted as `2.675` even
though its stored value is slightly below the mathematical decimal value.

The guarantee is **identical binary64 bits produce identical canonical bytes**.
Two computations that are mathematically equal but round to different binary64
bits intentionally produce different bytes. Making them equal would require a
domain-specific rounding rule and would discard evidence; producers that need
such normalization must do it before creating the log value and must specify it
in the model or feature-generation contract.

### Worked full-entry example

Suppose the producer creates this complete unsigned entry (the exact object
that is hashed and signed). The SHAP contribution came from `0.1 + 0.2` and has
binary64 bits `3fd3333333333334`; `confidence` has bits `3fda3d70a3d70a3d`.

```json
{
  "format_version": 2,
  "event_type": "classification_decision",
  "seq": 0,
  "ts_utc": "2026-07-13T12:00:00Z",
  "node_id": "node-01",
  "raw_csi_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "features_hash": "2222222222222222222222222222222222222222222222222222222222222222",
  "model_id": "model-v1",
  "model_config_hash": "3333333333333333333333333333333333333333333333333333333333333333",
  "class": "intrusion",
  "confidence": 0.41,
  "top_shap": [{"feature": "phase_variance", "contribution": 0.30000000000000004}],
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Its canonical `record_bytes` are exactly the following ASCII/UTF-8 bytes, with
no BOM and no trailing LF:

```text
{"class":"intrusion","confidence":0.41,"event_type":"classification_decision","features_hash":"2222222222222222222222222222222222222222222222222222222222222222","format_version":2,"model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","seq":0,"top_shap":[{"contribution":0.30000000000000004,"feature":"phase_variance"}],"ts_utc":"2026-07-13T12:00:00Z"}
```

### Float canonicalization test vectors

The `binary64 hex` column is the normative input and removes ambiguity caused
by parsing decimal source text. The input label is explanatory. The versioned,
machine-readable copy is
[`tests/vectors/float_canonicalization.json`](../tests/vectors/float_canonicalization.json).
These 25 scalar vectors are independent of the record schema and are unchanged
from chain format version 1. Full-record hashes and signatures below changed
because version-2 classification records add `format_version` and `event_type`.

| Input label | Binary64 hex | Canonical token | Divergence covered |
|---|---|---|---|
| `1.0` | `3ff0000000000000` | `1.0` | Float type marker on an integral value |
| `0.30000000000000004` | `3fd3333333333334` | `0.30000000000000004` | Required shortest-round-trip digits |
| `-0.0` | `8000000000000000` | `-0.0` | Negative-zero sign preservation |
| `0.0` | `0000000000000000` | `0.0` | Positive zero distinguishes the two zero bit patterns |
| `0.00001` | `3ee4f8b588e368f1` | `1e-05` | Fixed/scientific threshold and exponent padding |
| `1e21` | `444b1ae4d6e2ef50` | `1e+21` | Large-magnitude exponent notation |
| decimal integer `9007199254740993` converted to binary64 | `4340000000000000` | `9007199254740992.0` | First integer not exactly representable as binary64 |
| `5e-324` | `0000000000000001` | `5e-324` | Smallest positive subnormal |
| `2.225073858507201e-308` | `000fffffffffffff` | `2.225073858507201e-308` | Largest subnormal |
| `2.2250738585072014e-308` | `0010000000000000` | `2.2250738585072014e-308` | Smallest positive normal |
| `1.7976931348623157e308` | `7fefffffffffffff` | `1.7976931348623157e+308` | Largest finite value and three-digit exponent |
| decimal input `2.675` | `4005666666666666` | `2.675` | Decimal rounding-boundary value without naive rounding |
| SHAP contribution `0.41` | `3fda3d70a3d70a3d` | `0.41` | Representative explanation value |
| decimal input `1.23456789012345678` | `3ff3c0ca428c59fb` | `1.2345678901234567` | Binary64 rounding and 17-digit boundary |
| `-0.125` | `bfc0000000000000` | `-0.125` | Exactly representable negative fraction |
| `42.0` | `4045000000000000` | `42.0` | Integer-looking binary64 |
| `0.0001` | `3f1a36e2eb1c432d` | `0.0001` | Fixed-point lower threshold at `k = -4` |
| `10000000000000000.0` | `4341c37937e08000` | `1e+16` | Scientific upper threshold at `k = 16` |
| `999999999999999.9` | `430c6bf52633ffff` | `999999999999999.9` | Large value below scientific threshold |
| `0.00000012` | `3e801b2b29a4692b` | `1.2e-07` | Lowercase `e` and negative exponent padding |
| `100000000000000000000.0` | `4415af1d78b58c40` | `1e+20` | Python/Rust default notation divergence |
| `-12345.6789` | `c0c81cd6e631f8a1` | `-12345.6789` | Negative fixed-point value |
| NaN | `7ff8000000000000` | rejected | Non-finite value |
| positive infinity | `7ff0000000000000` | rejected | Non-finite value |
| negative infinity | `fff0000000000000` | rejected | Non-finite value |

### Integer-versus-float schema boundary

Chain format version 2, like version 1, does not pass JSON integers through float
canonicalization. The signed-64-bit JSON integer `9007199254740993` is valid
and emits exactly `9007199254740993`; only an explicit conversion to binary64
rounds it to the vector above. Likewise, integer `1` emits `1`, binary64 `1.0`
emits `1.0`, and the records hash differently. The current `confidence` schema
says `number`, so either representation can arrive from a producer. Producers
must preserve and consistently choose the intended numeric type. Changing this
boundary requires a new chain-format version; a verifier must not guess or
normalize it.

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
3. Construct the **unsigned object** from the exact common, event-type-specific,
   and managed unsigned fields defined above. Neither `record_hash` nor
   `signature` is present. Inapplicable event-type fields must not be added.
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
{"class":"normal","confidence":0.875,"event_type":"classification_decision","features_hash":"2222222222222222222222222222222222222222222222222222222222222222","format_version":2,"model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","seq":0,"top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}
```

Expected lowercase SHA-256:

```text
a3cf276f603ad38d4c36c6319a47f1aaf618ace6c00a5da65d33cbd3caaa6efb
```

Expected lowercase Ed25519 signature:

```text
e24926670ba994607ddabd50de2506d4e916ace4f35cc470e545015f512262d9122baf4e44a5db6ca5923f18ee2be9286d6f840bc8310fd882dd24fedafdd00d
```

The exact stored line is the following bytes plus one final `0x0a`:

```json
{"class":"normal","confidence":0.875,"event_type":"classification_decision","features_hash":"2222222222222222222222222222222222222222222222222222222222222222","format_version":2,"model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","record_hash":"a3cf276f603ad38d4c36c6319a47f1aaf618ace6c00a5da65d33cbd3caaa6efb","seq":0,"signature":"e24926670ba994607ddabd50de2506d4e916ace4f35cc470e545015f512262d9122baf4e44a5db6ca5923f18ee2be9286d6f840bc8310fd882dd24fedafdd00d","top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}
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
| `1.0` | `1.0` | `1fb4432bfe63a9cf6b54e8ae416ec5d11bd87d6669b527d8c801e54500c4287f` | `e2a179bc96914aecd5b680659f3158e6067adb64fb20a286a9690de84c56df7141ee3e3d1681d1c129a3f92685c1023baf04f642fbdfcb3aefdbf9bd9ef63f03` |
| `0.9532` | `0.9532` | `5d6c9cc40f8db9dcf9984ce87cc7889eec0e0694426d0a3d20e97efaa739afc7` | `b61ad135f9ea5fa3894646c74b4f6b6c410daa10bc7c47feb1a8a288b9bedf6efcbd93ce8291c798048899f0a428123ef9acc6c4838bce1372c9978705012c04` |
| `0.1 + 0.2` | `0.30000000000000004` | `576598c9ed876b0d040e3d1149883994d0f7e4f1f7800605d9d2552237e72ab6` | `33344ebde2b8cb80741e9e74e64c26342be691fb1924c0389ba802903d473b0949c54a91f837534881386f6e21293ccac5ade1764542c584eb1ae6ccc888ff0b` |
| `0.00001` | `1e-05` | `e6019ec3fc79d8c4e22ae378cdd5a8a1753f6bbb36ac847959e34031fae083cf` | `4545cf6255c52fe1a8ea9849621ac8c3a812570534057681227d212b2274535e0cbea61e30c8565d695fd9308a155093e546d67b81039a21bf9fc4f5edc53d0a` |

The complete scalar vector set appears in Float Canonicalization above.
Negative finite binary64 values are valid inside `top_shap` even though values
below zero are invalid for `confidence`.
