use std::cell::Cell;
use std::fmt::{self, Formatter};

use serde::Deserialize;
use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

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
pub fn command(body: &[u8], max_request_elements: usize) -> Result<Vec<Value>, ParseError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let remaining = Cell::new(max_request_elements);
    let exceeded = Cell::new(None);
    let values = CommandSeed {
        remaining: &remaining,
        exceeded: &exceeded,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| classify(exceeded.get()))?;
    deserializer.end().map_err(|_| ParseError::Invalid)?;
    Ok(values)
}

/// Parses a pipeline with independent command-count and request-wide JSON-node bounds.
pub fn pipeline(
    body: &[u8],
    max_commands: usize,
    max_request_elements: usize,
) -> Result<Vec<Vec<Value>>, ParseError> {
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
    type Value = Vec<Value>;

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
    type Value = Vec<Value>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Redis command array")
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
        Ok(values)
    }
}

struct PipelineSeed<'a> {
    max_commands: usize,
    remaining: &'a Cell<usize>,
    exceeded: &'a Cell<Option<LimitExceeded>>,
}

impl<'de> DeserializeSeed<'de> for PipelineSeed<'_> {
    type Value = Vec<Vec<Value>>;

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
    type Value = Vec<Vec<Value>>;

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
}
