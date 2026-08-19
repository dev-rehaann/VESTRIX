//! Canonical JSON parsing and serialization for Vestrix chain records.
//!
//! The chain format specifies Python 3.11 `json.dumps` output. In particular,
//! binary64 exponent formatting differs from serde_json, so floats are
//! rendered here instead of delegated to a general-purpose JSON serializer.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Failure to canonicalize a value forbidden by the chain format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizeError {
    NonFinite,
}

impl fmt::Display for CanonicalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NaN and infinity are not permitted")
    }
}

impl std::error::Error for CanonicalizeError {}

/// A JSON value parsed while rejecting duplicate object keys.
pub struct StrictValue(pub Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = i64::try_from(value)
                    .map_err(|_| E::custom("integer is outside the signed 64-bit range"))?;
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let number = Number::from_f64(value)
                    .ok_or_else(|| E::custom("NaN and infinity are not permitted"))?;
                Ok(StrictValue(Value::Number(number)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = object.next_entry::<String, StrictValue>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(de::Error::custom(format!("duplicate object key {key:?}")));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parse exactly one strict JSON value from UTF-8 text.
pub fn parse(input: &str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = StrictValue::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(value.0)
}

/// Serialize a JSON value using the chain format's canonical representation.
pub fn serialize(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_value(value: &Value, output: &mut String) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&format_number(value)?),
        Value::String(value) => {
            let escaped = serde_json::to_string(value).map_err(|error| error.to_string())?;
            output.push_str(&escaped);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_value(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                let escaped = serde_json::to_string(key).map_err(|error| error.to_string())?;
                output.push_str(&escaped);
                output.push(':');
                write_value(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn format_number(number: &Number) -> Result<String, String> {
    if let Some(value) = number.as_i64() {
        return Ok(value.to_string());
    }
    let value = number
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| "number is not a finite binary64 value".to_owned())?;
    canonicalize_float(value).map_err(|error| error.to_string())
}

/// Implement CHAIN_FORMAT.md `Float Canonicalization` for one binary64 value.
pub fn canonicalize_float(value: f64) -> Result<String, CanonicalizeError> {
    if !value.is_finite() {
        return Err(CanonicalizeError::NonFinite);
    }
    Ok(format_finite_float(value))
}

fn format_finite_float(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".to_owned()
        } else {
            "0.0".to_owned()
        };
    }

    let mut buffer = ryu::Buffer::new();
    let shortest = buffer.format_finite(value);
    let (negative, unsigned) = shortest
        .strip_prefix('-')
        .map_or((false, shortest), |rest| (true, rest));
    let (mantissa, explicit_exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, None), |(m, e)| (m, Some(e)));

    let decimal_position = mantissa.find('.').unwrap_or(mantissa.len());
    let mut digits: String = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect();
    let leading_zeroes = digits
        .chars()
        .take_while(|character| *character == '0')
        .count();
    digits.drain(..leading_zeroes);

    let explicit = explicit_exponent
        .and_then(|exponent| exponent.parse::<i32>().ok())
        .unwrap_or(0);
    let mut exponent = explicit + i32::try_from(decimal_position).unwrap_or(i32::MAX)
        - 1
        - i32::try_from(leading_zeroes).unwrap_or(i32::MAX);

    while digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        digits.push('0');
        exponent = 0;
    }

    let sign = if negative { "-" } else { "" };
    if !(-4..16).contains(&exponent) {
        let mut rendered = String::from(sign);
        rendered.push(digits.as_bytes()[0] as char);
        if digits.len() > 1 {
            rendered.push('.');
            rendered.push_str(&digits[1..]);
        }
        rendered.push('e');
        rendered.push(if exponent >= 0 { '+' } else { '-' });
        rendered.push_str(&format!("{:02}", exponent.unsigned_abs()));
        return rendered;
    }

    let mut rendered = String::from(sign);
    let point = exponent + 1;
    if point <= 0 {
        rendered.push_str("0.");
        for _ in 0..-point {
            rendered.push('0');
        }
        rendered.push_str(&digits);
    } else if usize::try_from(point).is_ok_and(|point| point < digits.len()) {
        let point = usize::try_from(point).expect("positive point fits usize");
        rendered.push_str(&digits[..point]);
        rendered.push('.');
        rendered.push_str(&digits[point..]);
    } else {
        rendered.push_str(&digits);
        let zeroes = usize::try_from(point).unwrap_or(usize::MAX) - digits.len();
        for _ in 0..zeroes {
            rendered.push('0');
        }
        rendered.push_str(".0");
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_cpython_json_dumps_float_ground_truth() {
        // Expected strings were generated by CPython's json.dumps with the
        // exact options in CHAIN_FORMAT.md; they are not hand-derived.
        let cases = [
            (1.0, "1.0"),
            (0.9532, "0.9532"),
            (0.1 + 0.2, "0.30000000000000004"),
            (0.00001, "1e-05"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (-0.125, "-0.125"),
            (0.0001, "0.0001"),
            (1_000_000_000_000_000.0, "1000000000000000.0"),
            (10_000_000_000_000_000.0, "1e+16"),
            (1.2345e20, "1.2345e+20"),
            (1.2e-7, "1.2e-07"),
        ];
        for (value, expected) in cases {
            let number = Number::from_f64(value).expect("test values are finite");
            assert_eq!(
                canonicalize_float(value).unwrap(),
                expected,
                "input {value:?}"
            );
            assert_eq!(
                serialize(&Value::Number(number)).unwrap(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn rejects_non_finite_floats() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(canonicalize_float(value), Err(CanonicalizeError::NonFinite));
        }
    }

    #[test]
    fn rejects_duplicate_nested_keys() {
        let error = parse(r#"{"top_shap":{"x":1,"x":2}}"#).unwrap_err();
        assert!(error.contains("duplicate object key \"x\""));
    }
}
