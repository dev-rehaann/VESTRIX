//! Streaming verification of canonical JSONL chain records.
//!
//! Every physical line is independently parsed and checked before its hash is
//! allowed to become the expected predecessor. Verification stops at the first
//! failure, so the reported sequence is deterministic and no later untrusted
//! data can mask an earlier fault.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const V1_FIELDS: [&str; 13] = [
    "seq",
    "ts_utc",
    "node_id",
    "raw_csi_hash",
    "features_hash",
    "model_id",
    "model_config_hash",
    "class",
    "confidence",
    "top_shap",
    "prev_hash",
    "record_hash",
    "signature",
];
const V2_INGESTION_FIELDS: [&str; 11] = [
    "format_version",
    "event_type",
    "seq",
    "ts_utc",
    "node_id",
    "raw_csi_hash",
    "collector_schema_version",
    "collector_sequence_number",
    "prev_hash",
    "record_hash",
    "signature",
];
const V2_CLASSIFICATION_FIELDS: [&str; 15] = [
    "format_version",
    "event_type",
    "seq",
    "ts_utc",
    "node_id",
    "raw_csi_hash",
    "features_hash",
    "model_id",
    "model_config_hash",
    "class",
    "confidence",
    "top_shap",
    "prev_hash",
    "record_hash",
    "signature",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    pub seq: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub records: u64,
    pub tip: Option<ChainTip>,
}

#[derive(Debug)]
pub struct ChainError {
    pub seq: u64,
    pub reason: String,
}

impl ChainError {
    fn at(seq: u64, reason: impl Into<String>) -> Self {
        Self {
            seq,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "chain verification failed at seq {}: {}",
            self.seq, self.reason
        )
    }
}

impl std::error::Error for ChainError {}

/// Verify an entire chain using a raw 32-byte Ed25519 public key.
pub fn verify_path(path: &Path, public_key: &[u8; 32]) -> Result<VerificationReport, ChainError> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|error| ChainError::at(0, format!("invalid Ed25519 public key: {error}")))?;
    let file = File::open(path)
        .map_err(|error| ChainError::at(0, format!("cannot open chain file: {error}")))?;
    verify_reader(BufReader::new(file), &key)
}

pub fn verify_reader<R: BufRead>(
    mut reader: R,
    key: &VerifyingKey,
) -> Result<VerificationReport, ChainError> {
    let mut expected_seq = 0_u64;
    let mut expected_prev = GENESIS_HASH.to_owned();
    let mut line = Vec::new();
    let mut tip = None;
    let mut chain_format_version = None;

    loop {
        line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| ChainError::at(expected_seq, format!("cannot read chain: {error}")))?;
        if bytes_read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            return Err(ChainError::at(expected_seq, "record is not LF-terminated"));
        }
        line.pop();
        if line.is_empty() {
            return Err(ChainError::at(expected_seq, "blank line is not permitted"));
        }

        let stored = std::str::from_utf8(&line)
            .map_err(|error| ChainError::at(expected_seq, format!("invalid UTF-8: {error}")))?;
        let value = canonical::parse(stored)
            .map_err(|error| ChainError::at(expected_seq, format!("invalid JSON: {error}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| ChainError::at(expected_seq, "record is not a JSON object"))?;
        let format_version =
            validate_schema(object).map_err(|reason| ChainError::at(expected_seq, reason))?;
        if let Some(expected) = chain_format_version {
            if format_version != expected {
                return Err(ChainError::at(expected_seq, "chain mixes format versions"));
            }
        } else {
            chain_format_version = Some(format_version);
        }

        let canonical_complete = canonical::serialize(&value).map_err(|error| {
            ChainError::at(expected_seq, format!("cannot serialize JSON: {error}"))
        })?;
        if canonical_complete != line {
            return Err(ChainError::at(expected_seq, "stored JSON is not canonical"));
        }

        let seq =
            integer_field(object, "seq").map_err(|reason| ChainError::at(expected_seq, reason))?;
        if seq != expected_seq {
            let failure = if seq > expected_seq {
                "sequence gap"
            } else {
                "sequence duplicate or out of order"
            };
            return Err(ChainError::at(
                expected_seq,
                format!("{failure}: found seq {seq}, expected {expected_seq}"),
            ));
        }
        let prev_hash = string_field(object, "prev_hash")
            .map_err(|reason| ChainError::at(expected_seq, reason))?;
        if prev_hash != expected_prev {
            return Err(ChainError::at(
                expected_seq,
                "hash link broken: prev_hash does not match the expected predecessor",
            ));
        }

        let record_hash = string_field(object, "record_hash")
            .map_err(|reason| ChainError::at(expected_seq, reason))?
            .to_owned();
        let signature_hex = string_field(object, "signature")
            .map_err(|reason| ChainError::at(expected_seq, reason))?;
        let mut unsigned = object.clone();
        unsigned.remove("record_hash");
        unsigned.remove("signature");
        let record_bytes = canonical::serialize(&Value::Object(unsigned)).map_err(|error| {
            ChainError::at(expected_seq, format!("cannot serialize JSON: {error}"))
        })?;
        let calculated = Sha256::digest(&record_bytes);
        if encode_hex(&calculated) != record_hash {
            return Err(ChainError::at(expected_seq, "record_hash mismatch"));
        }

        let signature_bytes = decode_hex_array::<64>(signature_hex).map_err(|reason| {
            ChainError::at(expected_seq, format!("invalid signature: {reason}"))
        })?;
        let signature = Signature::from_bytes(&signature_bytes);
        key.verify_strict(&record_bytes, &signature)
            .map_err(|_| ChainError::at(expected_seq, "Ed25519 signature verification failed"))?;

        tip = Some(ChainTip {
            seq,
            record_hash: record_hash.clone(),
        });
        expected_prev = record_hash;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| ChainError::at(expected_seq, "sequence counter overflow"))?;
    }

    Ok(VerificationReport {
        records: expected_seq,
        tip,
    })
}

fn validate_schema(object: &Map<String, Value>) -> Result<u64, String> {
    let (format_version, expected): (u64, BTreeSet<_>) = match object.get("format_version") {
        None => (1, V1_FIELDS.into_iter().collect()),
        Some(_) => {
            let version = integer_field(object, "format_version")?;
            if version != 2 {
                return Err("format_version must be integer 2".to_owned());
            }
            let fields = match string_field(object, "event_type")? {
                "ingestion_accepted" => V2_INGESTION_FIELDS.as_slice(),
                "classification_decision" => V2_CLASSIFICATION_FIELDS.as_slice(),
                _ => {
                    return Err(
                        "event_type must be ingestion_accepted or classification_decision"
                            .to_owned(),
                    );
                }
            };
            (version, fields.iter().copied().collect())
        }
    };
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if actual != expected {
        let missing: Vec<_> = expected.difference(&actual).copied().collect();
        let extra: Vec<_> = actual.difference(&expected).copied().collect();
        return Err(format!(
            "schema mismatch (missing: {}; extra: {})",
            display_names(&missing),
            display_names(&extra)
        ));
    }

    integer_field(object, "seq")?;
    validate_timestamp(string_field(object, "ts_utc")?)?;
    if string_field(object, "node_id")?.is_empty() {
        return Err("node_id must be non-empty".to_owned());
    }
    for field in ["raw_csi_hash", "prev_hash", "record_hash"] {
        validate_lower_hex(string_field(object, field)?, 64)
            .map_err(|reason| format!("{field} {reason}"))?;
    }
    validate_lower_hex(string_field(object, "signature")?, 128)
        .map_err(|reason| format!("signature {reason}"))?;

    let event_type = object.get("event_type").and_then(Value::as_str);
    if format_version == 1 || event_type == Some("classification_decision") {
        for field in ["model_id", "class"] {
            if string_field(object, field)?.is_empty() {
                return Err(format!("{field} must be non-empty"));
            }
        }
        for field in ["features_hash", "model_config_hash"] {
            validate_lower_hex(string_field(object, field)?, 64)
                .map_err(|reason| format!("{field} {reason}"))?;
        }
        let confidence = object
            .get("confidence")
            .and_then(Value::as_number)
            .ok_or_else(|| "confidence is not a number".to_owned())?
            .as_f64()
            .ok_or_else(|| "confidence is not a finite binary64 number".to_owned())?;
        if !(0.0..=1.0).contains(&confidence) {
            return Err("confidence is outside [0,1]".to_owned());
        }
    } else {
        if string_field(object, "collector_schema_version")?.is_empty() {
            return Err("collector_schema_version must be non-empty".to_owned());
        }
        integer_field(object, "collector_sequence_number")?;
    }
    Ok(format_version)
}

fn integer_field(object: &Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| format!("{field} is not a non-negative integer"))
}

fn string_field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is not a string"))
}

fn display_names(names: &[&str]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

fn validate_lower_hex(value: &str, length: usize) -> Result<(), &'static str> {
    if value.len() != length {
        return Err("has the wrong length");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("is not lowercase hexadecimal");
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let shape = bytes.len() >= 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.last() == Some(&b'Z')
        && (bytes.len() == 20 || (bytes.get(19) == Some(&b'.') && bytes.len() > 21));
    if !shape {
        return Err("ts_utc is not in YYYY-MM-DDTHH:MM:SS[.fraction]Z form".to_owned());
    }
    let digit_ranges = [0..4, 5..7, 8..10, 11..13, 14..16, 17..19];
    if digit_ranges
        .iter()
        .any(|range| !bytes[range.clone()].iter().all(u8::is_ascii_digit))
        || (bytes.len() > 20 && !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err("ts_utc contains non-digits in a numeric component".to_owned());
    }

    let year = decimal(&bytes[0..4]);
    let month = decimal(&bytes[5..7]);
    let day = decimal(&bytes[8..10]);
    let hour = decimal(&bytes[11..13]);
    let minute = decimal(&bytes[14..16]);
    let second = decimal(&bytes[17..19]);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err("ts_utc month is out of range".to_owned()),
    };
    if !(1..=max_day).contains(&day) {
        return Err("ts_utc day is out of range".to_owned());
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err("ts_utc time component is out of range".to_owned());
    }
    Ok(())
}

fn decimal(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}

pub fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    validate_lower_hex(value, N * 2).map_err(str::to_owned)?;
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2]);
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]);
        *byte = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hex was validated"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}
