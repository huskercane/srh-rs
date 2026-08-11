use std::cell::Cell;
use std::fmt::{self, Formatter};

use bytes::Bytes;
use serde::Deserialize;
use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::domain::convert::json_value_to_bytes;
use crate::ports::RedisCommand;

#[derive(Clone, Copy)]
pub enum ParseError {
    Invalid,
    PipelineTooLarge,
    RequestTooComplex,
}

#[derive(Clone, Copy)]
enum LimitExceeded {
    PipelineCommands,
    RequestElements,
}

/// Parses one command without materializing more than the request-wide JSON-node budget.
///
/// Arguments are converted to Redis bytes as they are deserialized rather than through an
/// intermediate `Vec<serde_json::Value>`: the tree was allocated only to be walked once and
/// thrown away, and every string in it was copied twice.
pub fn command(body: &[u8], max_request_elements: usize) -> Result<RedisCommand, ParseError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let remaining = Cell::new(max_request_elements);
    let exceeded = Cell::new(None);
    let command = CommandSeed {
        remaining: &remaining,
        exceeded: &exceeded,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| classify(exceeded.get()))?;
    deserializer.end().map_err(|_| ParseError::Invalid)?;
    Ok(command)
}

/// Parses a pipeline with independent command-count and request-wide JSON-node bounds.
pub fn pipeline(
    body: &[u8],
    max_commands: usize,
    max_request_elements: usize,
) -> Result<Vec<RedisCommand>, ParseError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let remaining = Cell::new(max_request_elements);
    let exceeded = Cell::new(None);
    let commands = PipelineSeed {
        max_commands,
        remaining: &remaining,
        exceeded: &exceeded,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| classify(exceeded.get()))?;
    deserializer.end().map_err(|_| ParseError::Invalid)?;
    Ok(commands)
}

fn classify(exceeded: Option<LimitExceeded>) -> ParseError {
    match exceeded {
        Some(LimitExceeded::PipelineCommands) => ParseError::PipelineTooLarge,
        Some(LimitExceeded::RequestElements) => ParseError::RequestTooComplex,
        None => ParseError::Invalid,
    }
}

struct CommandSeed<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for CommandSeed<'_> {
    type Value = RedisCommand;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        charge::<D::Error>(self.remaining, self.exceeded)?;
        deserializer.deserialize_seq(CommandVisitor {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })
    }
}

struct CommandVisitor<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> Visitor<'de> for CommandVisitor<'_> {
    type Value = RedisCommand;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Redis command array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // The command name must be a JSON string to be a command name at all. Emptiness and
        // policy stay in `domain::acl`, which is the only place allowed to decide them.
        let Some(name) = sequence.next_element_seed(NameSeed {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })?
        else {
            return Err(A::Error::custom("command array is empty"));
        };
        let mut args =
            Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.remaining.get()));
        while let Some(argument) = sequence.next_element_seed(ArgumentSeed {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })? {
            args.push(argument);
        }
        Ok(RedisCommand { name, args })
    }
}

struct PipelineSeed<'a> {
    max_commands: usize,
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for PipelineSeed<'_> {
    type Value = Vec<RedisCommand>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        charge::<D::Error>(self.remaining, self.exceeded)?;
        deserializer.deserialize_seq(PipelineVisitor {
            max_commands: self.max_commands,
            remaining: self.remaining,
            exceeded: self.exceeded,
        })
    }
}

struct PipelineVisitor<'a> {
    max_commands: usize,
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> Visitor<'de> for PipelineVisitor<'_> {
    type Value = Vec<RedisCommand>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of Redis command arrays")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut commands =
            Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.max_commands));
        while commands.len() < self.max_commands {
            match sequence.next_element_seed(CommandSeed {
                remaining: self.remaining,
                exceeded: self.exceeded,
            })? {
                Some(command) => commands.push(command),
                None => return Ok(commands),
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            self.exceeded.set(Some(LimitExceeded::PipelineCommands));
            Err(A::Error::custom("pipeline command limit exceeded"))
        } else {
            Ok(commands)
        }
    }
}

struct NameSeed<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for NameSeed<'_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        charge::<D::Error>(self.remaining, self.exceeded)?;
        String::deserialize(deserializer)
    }
}

struct ArgumentSeed<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for ArgumentSeed<'_> {
    type Value = Bytes;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        charge::<D::Error>(self.remaining, self.exceeded)?;
        deserializer.deserialize_any(ArgumentVisitor {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })
    }
}

/// Produces argument bytes directly for scalars, and falls back to the shared
/// [`json_value_to_bytes`] contract for the nested values that must be re-serialized.
struct ArgumentVisitor<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> Visitor<'de> for ArgumentVisitor<'_> {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Redis command argument")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Bytes::from_static(if value { b"true" } else { b"false" }))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Bytes::from(serde_json::Number::from(value).to_string()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Bytes::from(serde_json::Number::from(value).to_string()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| Bytes::from(number.to_string()))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Bytes::copy_from_slice(value.as_bytes()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        // An escaped string arrives owned; taking it avoids the copy `visit_str` needs.
        Ok(Bytes::from(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Bytes::from_static(b"null"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Bytes::from_static(b"null"))
    }

    fn visit_seq<A>(self, sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        nested(
            ValueVisitor {
                remaining: self.remaining,
                exceeded: self.exceeded,
            }
            .visit_seq(sequence)?,
        )
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        nested(
            ValueVisitor {
                remaining: self.remaining,
                exceeded: self.exceeded,
            }
            .visit_map(map)?,
        )
    }
}

fn nested<E>(value: Value) -> Result<Bytes, E>
where
    E: serde::de::Error,
{
    json_value_to_bytes(&value).map_err(|_| E::custom("argument is not representable"))
}

struct ValueSeed<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        charge::<D::Error>(self.remaining, self.exceeded)?;
        deserializer.deserialize_any(ValueVisitor {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })
    }
}

struct ValueVisitor<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values =
            Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.remaining.get()));
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values =
            serde_json::Map::with_capacity(map.size_hint().unwrap_or(0).min(self.remaining.get()));
        while let Some(key) = map.next_key_seed(KeySeed {
            remaining: self.remaining,
            exceeded: self.exceeded,
        })? {
            let value = map.next_value_seed(ValueSeed {
                remaining: self.remaining,
                exceeded: self.exceeded,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct KeySeed<'a> {
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        charge::<D::Error>(self.remaining, self.exceeded)?;
        String::deserialize(deserializer)
    }
}

fn charge<E>(remaining: &Cell<usize>, exceeded: &Cell<Option<LimitExceeded>>) -> Result<(), E>
where
    E: serde::de::Error,
{
    let Some(next) = remaining.get().checked_sub(1) else {
        exceeded.set(Some(LimitExceeded::RequestElements));
        return Err(E::custom("request element budget exceeded"));
    };
    remaining.set(next);
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rejects_flat_and_nested_nodes_before_materializing_beyond_the_cap() {
        let flat = serde_json::to_vec(&vec![json!("A"); 10_000]).unwrap();
        assert!(matches!(
            command(&flat, 1000),
            Err(ParseError::RequestTooComplex)
        ));

        let nested = serde_json::to_vec(&json!(["SET", "key", vec![1; 10_000]])).unwrap();
        assert!(matches!(
            command(&nested, 1000),
            Err(ParseError::RequestTooComplex)
        ));
    }

    #[test]
    fn distinguishes_pipeline_length_from_request_node_budget() {
        let body = serde_json::to_vec(&vec![vec![json!("PING")]; 1001]).unwrap();
        assert!(matches!(
            pipeline(&body, 1000, 10_000),
            Err(ParseError::PipelineTooLarge)
        ));

        let body = serde_json::to_vec(&vec![vec![json!("A"); 1001]]).unwrap();
        assert!(matches!(
            pipeline(&body, 1000, 1000),
            Err(ParseError::RequestTooComplex)
        ));
    }

    #[test]
    fn scalar_arguments_match_the_shared_conversion() {
        // The deserializer builds scalar arguments itself instead of going through
        // `json_value_to_bytes`. This is the lock that keeps the two encodings identical.
        for scalar in [
            json!("text"),
            json!("es\"caped"),
            json!(100),
            json!(-7),
            json!(1.5),
            json!(true),
            json!(false),
            Value::Null,
        ] {
            let body = serde_json::to_vec(&json!(["CMD", scalar])).unwrap();
            let parsed = command(&body, 100).ok().expect("scalar argument parses");
            assert_eq!(
                parsed.args,
                vec![json_value_to_bytes(&scalar).unwrap()],
                "argument encoding drifted for {scalar}"
            );
        }
    }

    #[test]
    fn nested_arguments_are_re_serialized_as_json_text() {
        let body = serde_json::to_vec(&json!(["SET", "key", {"a": 1}, ["x", 2]])).unwrap();
        let parsed = command(&body, 100).ok().expect("nested arguments parse");
        assert_eq!(
            parsed.args,
            [r#"key"#, r#"{"a":1}"#, r#"["x",2]"#].map(Bytes::from)
        );
    }

    #[test]
    fn a_command_name_must_be_a_string_and_present() {
        for body in [
            &b"[]"[..],
            &b"[1,\"key\"]"[..],
            &b"[null]"[..],
            &b"[[\"GET\"]]"[..],
        ] {
            assert!(
                matches!(command(body, 100), Err(ParseError::Invalid)),
                "accepted a command with no usable name: {}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
