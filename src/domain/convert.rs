use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde_json::Value;

use crate::domain::resp::RespValue;
use crate::ports::RedisCommand;

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

/// Convert one JSON command array into raw Redis command bytes.
pub fn json_args_to_redis(values: &[Value]) -> Result<RedisCommand, ConversionError> {
    let Some(Value::String(name)) = values.first() else {
        return Err(ConversionError::InvalidCommand);
    };
    if name.is_empty() {
        return Err(ConversionError::InvalidCommand);
    }

    let args = values[1..]
        .iter()
        .map(json_value_to_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RedisCommand {
        name: name.clone(),
        args,
    })
}

fn json_value_to_bytes(value: &Value) -> Result<Bytes, ConversionError> {
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

/// Convert a transport-independent RESP2 value to JSON within a shared budget.
pub fn redis_value_to_json(
    value: RespValue,
    encoding: Encoding,
    budget: &mut usize,
) -> Result<Value, ConversionError> {
    convert_within_depth(value, encoding, budget, MAX_DEPTH)
}

fn convert_within_depth(
    value: RespValue,
    encoding: Encoding,
    budget: &mut usize,
    depth_remaining: usize,
) -> Result<Value, ConversionError> {
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
                let encoded_len = base64_encoded_len(value.len())?;
                charge(budget, encoded_len)?;
                Ok(Value::String(STANDARD.encode(value.as_bytes())))
            } else {
                charge(budget, value.len())?;
                Ok(Value::String(value))
            }
        }
        RespValue::Bulk(value) => {
            if encoding == Encoding::Base64 {
                let encoded_len = base64_encoded_len(value.len())?;
                charge(budget, encoded_len)?;
                Ok(Value::String(STANDARD.encode(&value)))
            } else {
                let value = String::from_utf8_lossy(&value).into_owned();
                charge(budget, value.len())?;
                Ok(Value::String(value))
            }
        }
        RespValue::Int(value) => Ok(Value::Number(value.into())),
        RespValue::Nil => Ok(Value::Null),
        RespValue::Array(values) => values
            .into_iter()
            .map(|value| convert_within_depth(value, encoding, budget, depth_remaining))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
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

    #[test]
    fn converts_all_json_argument_kinds() {
        let command = json_args_to_redis(&[
            json!("SET"),
            json!("key"),
            json!(100),
            json!(1.5),
            json!(true),
            Value::Null,
            json!({"a": 1}),
            json!(["x", 2]),
        ])
        .unwrap();
        assert_eq!(command.name, "SET");
        assert_eq!(
            command.args,
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
    fn rejects_missing_non_string_and_empty_command_names() {
        for values in [vec![], vec![Value::Null], vec![json!("")]] {
            assert_eq!(
                json_args_to_redis(&values),
                Err(ConversionError::InvalidCommand)
            );
        }
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
            redis_value_to_json(value, Encoding::None, &mut budget).unwrap(),
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
            redis_value_to_json(value, Encoding::Base64, &mut budget).unwrap(),
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
            redis_value_to_json(value, Encoding::None, &mut budget),
            Err(ConversionError::ResponseTooLarge)
        );
    }

    fn nest(depth: usize) -> RespValue {
        (0..depth).fold(RespValue::Int(1), |inner, _| RespValue::Array(vec![inner]))
    }

    #[test]
    fn nesting_is_bounded_without_exhausting_the_stack() {
        let mut budget = usize::MAX;
        assert!(redis_value_to_json(nest(MAX_DEPTH - 1), Encoding::None, &mut budget).is_ok());
        // Deliberately just past the limit rather than enormous: dropping a
        // deeply nested `RespValue` is itself recursive, so the test value must
        // stay shallow enough to destroy safely.
        assert_eq!(
            redis_value_to_json(nest(MAX_DEPTH + 8), Encoding::None, &mut budget),
            Err(ConversionError::ResponseTooLarge),
            "a reply nested past MAX_DEPTH must be refused, not recursed"
        );
    }

    #[test]
    fn base64_budget_uses_exact_padded_size() {
        let mut exact = NODE_COST + 4;
        redis_value_to_json(
            RespValue::Bulk(Bytes::from_static(b"x")),
            Encoding::Base64,
            &mut exact,
        )
        .unwrap();
        assert_eq!(exact, 0);
    }
}
