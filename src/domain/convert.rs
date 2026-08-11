use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::ser::{Serialize, SerializeSeq, Serializer};
use serde_json::Value;

use crate::domain::resp::RespValue;

const NODE_COST: usize = 8;

/// Maximum RESP array nesting accepted during conversion. Real Redis replies
/// nest two or three deep; anything past this is a scripted or hostile reply
/// and must not be allowed to recurse the stack unbounded.
pub const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    None,
    Base64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionError {
    InvalidCommand,
    ResponseTooLarge,
}

/// Converts one JSON command argument to raw Redis bytes.
///
/// This is the contract for argument encoding. `http::parse` produces the scalar cases
/// directly from the deserializer without building a [`Value`] and calls this only for
/// nested arrays and objects; `parse`'s `scalar_arguments_match_the_shared_conversion`
/// test pins the two paths together.
pub fn json_value_to_bytes(value: &Value) -> Result<Bytes, ConversionError> {
    let text = match value {
        Value::String(value) => return Ok(Bytes::copy_from_slice(value.as_bytes())),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).map_err(|_| ConversionError::InvalidCommand)?
        }
    };
    Ok(Bytes::from(text))
}

/// Charges a RESP2 reply against the shared response budget and bounds its nesting.
///
/// This runs to completion *before* any of the reply is written, because exceeding the
/// budget must fail the whole request with `ResponseTooLarge` (502) rather than truncate a
/// response that has already been committed to. [`ResponseJson`] therefore serializes
/// infallibly, and relies on this call having already refused anything too deep to recurse.
pub fn charge_response_budget(
    value: &RespValue,
    encoding: Encoding,
    budget: &mut usize,
) -> Result<(), ConversionError> {
    charge_within_depth(value, encoding, budget, MAX_DEPTH)
}

fn charge_within_depth(
    value: &RespValue,
    encoding: Encoding,
    budget: &mut usize,
    depth_remaining: usize,
) -> Result<(), ConversionError> {
    // The budget bounds total size but not nesting, and recursion here is stack
    // depth. A Lua script can return arbitrarily nested tables, so cap it —
    // `ResponseTooLarge` rather than a transport error because the backend is
    // healthy, and Phase 4's breaker must not count this (see `ExecError`).
    let depth_remaining = depth_remaining
        .checked_sub(1)
        .ok_or(ConversionError::ResponseTooLarge)?;
    charge(budget, NODE_COST)?;
    match value {
        RespValue::Simple(value) => {
            if encoding == Encoding::Base64 && value != "OK" {
                charge(budget, base64_encoded_len(value.len())?)
            } else {
                charge(budget, value.len())
            }
        }
        RespValue::Bulk(value) => {
            if encoding == Encoding::Base64 {
                charge(budget, base64_encoded_len(value.len())?)
            } else {
                // Charge what will actually be written: lossy conversion expands every
                // invalid byte into a three-byte replacement character. Valid UTF-8 — the
                // overwhelmingly common case — borrows, so this does not allocate.
                charge(budget, String::from_utf8_lossy(value).len())
            }
        }
        RespValue::Int(_) | RespValue::Nil => Ok(()),
        RespValue::Array(values) => values
            .iter()
            .try_for_each(|value| charge_within_depth(value, encoding, budget, depth_remaining)),
    }
}

/// Serializes a RESP2 reply as Upstash JSON straight into the response body.
///
/// Building a `serde_json::Value` first would allocate a `String` for every bulk value and
/// a `Vec` for every array, then walk the whole tree again to write it. Writing through
/// the serializer skips that: a bulk value that is already valid UTF-8 is borrowed rather
/// than copied.
///
/// Callers must charge [`charge_response_budget`] first — that is what bounds the nesting
/// this type recurses over.
pub struct ResponseJson<'a> {
    value: &'a RespValue,
    encoding: Encoding,
}

impl<'a> ResponseJson<'a> {
    pub fn new(value: &'a RespValue, encoding: Encoding) -> Self {
        Self { value, encoding }
    }
}

impl Serialize for ResponseJson<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.value {
            RespValue::Simple(value) => {
                if self.encoding == Encoding::Base64 && value != "OK" {
                    serializer.serialize_str(&STANDARD.encode(value.as_bytes()))
                } else {
                    serializer.serialize_str(value)
                }
            }
            RespValue::Bulk(value) => {
                if self.encoding == Encoding::Base64 {
                    // Encodes from the original raw bytes, never from a lossy string: that
                    // is the entire reason the base64 encoding exists.
                    serializer.serialize_str(&STANDARD.encode(value))
                } else {
                    serializer.serialize_str(&String::from_utf8_lossy(value))
                }
            }
            RespValue::Int(value) => serializer.serialize_i64(*value),
            RespValue::Nil => serializer.serialize_none(),
            RespValue::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&Self::new(value, self.encoding))?;
                }
                sequence.end()
            }
        }
    }
}

fn base64_encoded_len(input_len: usize) -> Result<usize, ConversionError> {
    input_len
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|groups| groups.checked_mul(4))
        .ok_or(ConversionError::ResponseTooLarge)
}

fn charge(budget: &mut usize, amount: usize) -> Result<(), ConversionError> {
    *budget = budget
        .checked_sub(amount)
        .ok_or(ConversionError::ResponseTooLarge)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Charges the budget and renders in one step, the way a handler does.
    fn render(
        value: &RespValue,
        encoding: Encoding,
        budget: &mut usize,
    ) -> Result<Value, ConversionError> {
        charge_response_budget(value, encoding, budget)?;
        Ok(serde_json::to_value(ResponseJson::new(value, encoding))
            .expect("RESP rendering is infallible"))
    }

    #[test]
    fn converts_all_json_argument_kinds() {
        let arguments = [
            json!("key"),
            json!(100),
            json!(1.5),
            json!(true),
            Value::Null,
            json!({"a": 1}),
            json!(["x", 2]),
        ];
        let converted = arguments
            .iter()
            .map(json_value_to_bytes)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            converted,
            [
                "key",
                "100",
                "1.5",
                "true",
                "null",
                "{\"a\":1}",
                "[\"x\",2]"
            ]
            .map(Bytes::from)
        );
    }

    #[test]
    fn converts_every_resp2_value_recursively() {
        let value = RespValue::Array(vec![
            RespValue::Simple("OK".to_owned()),
            RespValue::Bulk(Bytes::from_static(b"bar")),
            RespValue::Int(42),
            RespValue::Nil,
            RespValue::Array(vec![RespValue::Bulk(Bytes::from_static(&[0xff, b'a']))]),
        ]);
        let mut budget = 1024;
        assert_eq!(
            render(&value, Encoding::None, &mut budget).unwrap(),
            json!(["OK", "bar", 42, null, ["�a"]])
        );
    }

    #[test]
    fn base64_encodes_original_bytes_and_preserves_ok() {
        let value = RespValue::Array(vec![
            RespValue::Simple("OK".to_owned()),
            RespValue::Simple("bar".to_owned()),
            RespValue::Bulk(Bytes::from_static(&[0xff, 0xfe, 0x00, 0x01])),
            RespValue::Int(1),
            RespValue::Nil,
        ]);
        let mut budget = 1024;
        assert_eq!(
            render(&value, Encoding::Base64, &mut budget).unwrap(),
            json!(["OK", "YmFy", "//4AAQ==", 1, null])
        );
    }

    #[test]
    fn response_budget_is_shared_and_fails_immediately() {
        let value = RespValue::Array(vec![
            RespValue::Bulk(Bytes::from_static(b"first")),
            RespValue::Bulk(Bytes::from_static(b"second")),
        ]);
        let mut budget = NODE_COST * 3 + "first".len() + "second".len() - 1;
        assert_eq!(
            render(&value, Encoding::None, &mut budget),
            Err(ConversionError::ResponseTooLarge)
        );
    }

    #[test]
    fn invalid_utf8_is_charged_at_its_expanded_length() {
        // Each invalid byte renders as U+FFFD, which is three bytes on the wire. Charging
        // the raw length would let a reply of invalid bytes spend triple its budget.
        let value = RespValue::Bulk(Bytes::from_static(&[0xff, 0xff]));
        let mut exact = NODE_COST + 6;
        assert!(render(&value, Encoding::None, &mut exact).is_ok());
        assert_eq!(exact, 0);

        let mut short = NODE_COST + 5;
        assert_eq!(
            render(&value, Encoding::None, &mut short),
            Err(ConversionError::ResponseTooLarge)
        );
    }

    fn nest(depth: usize) -> RespValue {
        (0..depth).fold(RespValue::Int(1), |inner, _| RespValue::Array(vec![inner]))
    }

    #[test]
    fn nesting_is_bounded_without_exhausting_the_stack() {
        let mut budget = usize::MAX;
        assert!(render(&nest(MAX_DEPTH - 1), Encoding::None, &mut budget).is_ok());
        // Deliberately just past the limit rather than enormous: dropping a
        // deeply nested `RespValue` is itself recursive, so the test value must
        // stay shallow enough to destroy safely.
        assert_eq!(
            render(&nest(MAX_DEPTH + 8), Encoding::None, &mut budget),
            Err(ConversionError::ResponseTooLarge),
            "a reply nested past MAX_DEPTH must be refused, not recursed"
        );
    }

    #[test]
    fn base64_budget_uses_exact_padded_size() {
        let mut exact = NODE_COST + 4;
        render(
            &RespValue::Bulk(Bytes::from_static(b"x")),
            Encoding::Base64,
            &mut exact,
        )
        .unwrap();
        assert_eq!(exact, 0);
    }
}
