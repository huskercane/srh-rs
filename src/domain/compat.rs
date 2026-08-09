use bytes::Bytes;

use crate::ports::RedisCommand;

/// Applies the small argument normalizations required by the Upstash wire contract.
pub fn normalize(mut command: RedisCommand) -> RedisCommand {
    if command.name == "GEODIST"
        && let Some(unit) = command.args.last_mut()
        && matches!(unit.as_ref(), b"M" | b"KM" | b"FT" | b"MI")
    {
        *unit = Bytes::from(unit.to_ascii_lowercase());
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geodist_units_match_plain_redis_case_requirements() {
        let command = RedisCommand {
            name: "GEODIST".to_owned(),
            args: ["key", "from", "to", "KM"]
                .into_iter()
                .map(Bytes::from)
                .collect(),
        };
        assert_eq!(normalize(command).args.last().unwrap().as_ref(), b"km");
    }

    #[test]
    fn unrelated_arguments_are_preserved_byte_for_byte() {
        let command = RedisCommand {
            name: "SET".to_owned(),
            args: vec![Bytes::from_static(b"key"), Bytes::from_static(b"MI")],
        };
        assert_eq!(normalize(command.clone()), command);
    }
}
