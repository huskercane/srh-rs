use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::domain::identity::Identity;
use crate::ports::RedisCommand;

// These commands may inspect or control the server, topology, or replication state. The
// protocol/session subset is also a correctness boundary for pooled connections: HELLO changes
// the RESP version for the next borrower, while SELECT and SWAPDB escape DB-index isolation.
const HARD_DENY: &[&str] = &[
    "CONFIG",
    "SHUTDOWN",
    "DEBUG",
    "SLAVEOF",
    "REPLICAOF",
    "MIGRATE",
    "MODULE",
    "SAVE",
    "BGSAVE",
    "BGREWRITEAOF",
    "LASTSAVE",
    "ACL",
    "CLIENT",
    "CLUSTER",
    "LATENCY",
    "MONITOR",
    "PSYNC",
    "SYNC",
    "FAILOVER",
    "RESET",
    "SLOWLOG",
    "COMMAND",
    "MEMORY",
    "HELLO",
    "SELECT",
    "SWAPDB",
    "AUTH",
    "QUIT",
    // Redis transactions and WATCH state outlive one HTTP request on a pooled connection.
    // Allowing them lets one caller queue later callers' commands and receive their results.
    "MULTI",
    "EXEC",
    "DISCARD",
    "WATCH",
    "UNWATCH",
    "SUBSCRIBE",
    "PSUBSCRIBE",
    "UNSUBSCRIBE",
    "PUNSUBSCRIBE",
    "SSUBSCRIBE",
    "SUNSUBSCRIBE",
    "PUBLISH",
    "PUBSUB",
    // Blocking commands can pin one of the bounded pool connections indefinitely.
    "BLPOP",
    "BRPOP",
    "BLMOVE",
    "BRPOPLPUSH",
    "BLMPOP",
    "BZPOPMIN",
    "BZPOPMAX",
    "BZMPOP",
    "WAIT",
    "WAITAOF",
    "SCRIPT",
    "FUNCTION",
];

const SCRIPTING: &[&str] = &[
    "EVAL",
    "EVALSHA",
    "EVALSHA_RO",
    "EVAL_RO",
    "FCALL",
    "FCALL_RO",
];

const DEFAULT_BLOCK: &[&str] = &["FLUSHALL", "FLUSHDB", "KEYS", "RANDOMKEY", "INFO", "DBSIZE"];

const READ_COMMANDS: &[&str] = &[
    "GET",
    "MGET",
    "GETRANGE",
    "STRLEN",
    "EXISTS",
    "TYPE",
    "TTL",
    "PTTL",
    "EXPIRETIME",
    "PEXPIRETIME",
    "HGET",
    "HMGET",
    "HGETALL",
    "HKEYS",
    "HVALS",
    "HLEN",
    "HEXISTS",
    "HSTRLEN",
    "HRANDFIELD",
    "LRANGE",
    "LLEN",
    "LINDEX",
    "LPOS",
    "SMEMBERS",
    "SISMEMBER",
    "SMISMEMBER",
    "SCARD",
    "SRANDMEMBER",
    "SINTER",
    "SUNION",
    "SDIFF",
    "SINTERCARD",
    "ZRANGE",
    "ZRANGEBYSCORE",
    "ZRANGEBYLEX",
    "ZREVRANGE",
    "ZREVRANGEBYSCORE",
    "ZREVRANGEBYLEX",
    "ZSCORE",
    "ZMSCORE",
    "ZCARD",
    "ZCOUNT",
    "ZLEXCOUNT",
    "ZRANK",
    "ZREVRANK",
    "ZRANDMEMBER",
    "GETBIT",
    "BITCOUNT",
    "BITPOS",
    "BITFIELD_RO",
    "XRANGE",
    "XREVRANGE",
    "XLEN",
    "XREAD",
    "XINFO",
    "GEOPOS",
    "GEODIST",
    "GEOHASH",
    "GEOSEARCH",
    "PFCOUNT",
    "OBJECT",
    "DUMP",
    "TOUCH",
    "TIME",
    "PING",
    "ECHO",
    "SORT_RO",
    "LCS",
    "SUBSTR",
];

/// A pure command-policy rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AclError {
    InvalidCommand,
    Forbidden(String),
}

/// Checks one converted command against an authenticated identity.
///
/// Arguments arrive already encoded as the bytes that will be sent to Redis. That is the
/// same encoding the old `Value`-based check applied before comparing, so the matching is
/// unchanged — a JSON number, bool, null, array or object still renders to text that
/// cannot collide with a keyword — and the scripting check no longer re-converts the
/// script body just to digest it.
pub fn check(identity: &Identity, command: &RedisCommand) -> Result<(), AclError> {
    let name = command.name.as_str();
    if name.is_empty() {
        return Err(AclError::InvalidCommand);
    }
    let name = name.to_ascii_uppercase();
    let admin_allowed = identity.is_admin && admin_allow(&name, command.args.first());

    // An explicit admin allowlist fails closed as Redis adds commands. An exemption with
    // carve-outs would accidentally permit hazards such as MODULE LOAD, MIGRATE, or SLAVEOF.
    if HARD_DENY.contains(&name.as_str()) && !admin_allowed {
        return Err(denied(&name));
    }

    check_scripting(identity, &name, command)?;

    if matches!(name.as_str(), "XREAD" | "XREADGROUP")
        && command
            .args
            .iter()
            .any(|argument| argument.as_ref().eq_ignore_ascii_case(b"BLOCK"))
    {
        return Err(AclError::Forbidden(
            "NOPERM blocking XREAD is not allowed".to_owned(),
        ));
    }

    // SORT_RO is read-only with respect to writes, not with respect to keys referenced by
    // BY/GET. Phase 8 will extend this hook to the rest of the key-spec policy.
    if identity.key_prefix.is_some()
        && matches!(name.as_str(), "SORT" | "SORT_RO")
        && command.args.iter().any(|argument| {
            argument.as_ref().eq_ignore_ascii_case(b"BY")
                || argument.as_ref().eq_ignore_ascii_case(b"GET")
        })
    {
        return Err(denied(&name));
    }

    if identity.blocked_commands.contains(&name) {
        return Err(denied(&name));
    }
    let explicitly_allowed = identity
        .allowed_commands
        .as_ref()
        .is_some_and(|commands| commands.contains(&name));
    if !identity.legacy
        && DEFAULT_BLOCK.contains(&name.as_str())
        && !explicitly_allowed
        && !admin_allowed
    {
        return Err(denied(&name));
    }
    if identity
        .allowed_commands
        .as_ref()
        .is_some_and(|commands| !commands.contains(&name))
    {
        return Err(denied(&name));
    }
    if identity.read_only && !READ_COMMANDS.contains(&name.as_str()) {
        return Err(denied(&name));
    }
    Ok(())
}

fn check_scripting(
    identity: &Identity,
    name: &str,
    command: &RedisCommand,
) -> Result<(), AclError> {
    if !SCRIPTING.contains(&name) {
        return Ok(());
    }
    // SHA-1 script digests and function names cannot be mapped to an approved SHA-256 body,
    // so EVALSHA and FCALL variants always fail closed.
    if !matches!(name, "EVAL" | "EVAL_RO") || identity.allowed_script_sha256.is_empty() {
        return Err(denied(name));
    }
    let script = command.args.first().ok_or_else(|| denied(name))?;
    let digest = hex_digest(&Sha256::digest(script));
    if !identity.allowed_script_sha256.contains(&digest) {
        return Err(denied(name));
    }
    Ok(())
}

fn admin_allow(name: &str, subcommand: Option<&Bytes>) -> bool {
    let subcommand = subcommand.map(|value| String::from_utf8_lossy(value).to_ascii_uppercase());
    matches!(
        (name, subcommand.as_deref()),
        ("CONFIG", Some("GET"))
            | ("CLIENT", Some("LIST" | "INFO"))
            | ("SLOWLOG", Some("GET" | "LEN"))
            | ("INFO", _)
            | ("COMMAND", Some("COUNT" | "INFO" | "DOCS"))
            | ("LATENCY", Some("HISTORY" | "LATEST"))
            | ("MEMORY", Some("USAGE" | "STATS" | "DOCTOR"))
            | ("ACL", Some("WHOAMI"))
    )
}

fn denied(name: &str) -> AclError {
    AclError::Forbidden(format!(
        "NOPERM this token does not have permission to run '{name}'"
    ))
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::*;

    fn identity() -> Identity {
        Identity {
            subject: "subject".to_owned(),
            bucket_key: "bucket".to_owned(),
            pool: "pool".to_owned(),
            read_only: false,
            is_admin: false,
            legacy: false,
            allowed_commands: None,
            blocked_commands: HashSet::new(),
            allowed_script_sha256: HashSet::new(),
            key_prefix: None,
        }
    }

    /// Builds the converted command a request would produce from a JSON array literal,
    /// using the same argument encoding `http::parse` applies.
    fn parsed(command: &Value) -> RedisCommand {
        let values = command.as_array().expect("command array");
        RedisCommand {
            name: values
                .first()
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            args: values[1..]
                .iter()
                .map(|value| {
                    crate::domain::convert::json_value_to_bytes(value)
                        .expect("test arguments are representable")
                })
                .collect(),
        }
    }

    fn assert_denied(identity: &Identity, command: Value) {
        assert!(matches!(
            check(identity, &parsed(&command)),
            Err(AclError::Forbidden(_))
        ));
    }

    #[test]
    fn read_only_policy_matches_the_corrected_command_set() {
        let mut identity = identity();
        identity.read_only = true;
        for command in [
            json!(["GET", "key"]),
            json!(["XREAD", "STREAMS", "key", "0"]),
        ] {
            check(&identity, &parsed(&command)).unwrap();
        }
        for command in [
            json!(["SET", "key", "v"]),
            json!(["SCAN", 0]),
            json!(["KEYS", "*"]),
        ] {
            assert_denied(&identity, command);
        }
    }

    #[test]
    fn hard_denies_have_no_non_admin_escape_hatch() {
        let identity = identity();
        // Keep this literal independent from HARD_DENY: deleting a production entry must not
        // delete its regression assertion at the same time.
        for name in [
            "CONFIG",
            "SHUTDOWN",
            "DEBUG",
            "SLAVEOF",
            "REPLICAOF",
            "MIGRATE",
            "MODULE",
            "SAVE",
            "BGSAVE",
            "BGREWRITEAOF",
            "LASTSAVE",
            "ACL",
            "CLIENT",
            "CLUSTER",
            "LATENCY",
            "MONITOR",
            "PSYNC",
            "SYNC",
            "FAILOVER",
            "RESET",
            "SLOWLOG",
            "COMMAND",
            "MEMORY",
            "HELLO",
            "SELECT",
            "SWAPDB",
            "AUTH",
            "QUIT",
            "MULTI",
            "EXEC",
            "DISCARD",
            "WATCH",
            "UNWATCH",
            "SUBSCRIBE",
            "PSUBSCRIBE",
            "UNSUBSCRIBE",
            "PUNSUBSCRIBE",
            "SSUBSCRIBE",
            "SUNSUBSCRIBE",
            "PUBLISH",
            "PUBSUB",
            "BLPOP",
            "BRPOP",
            "BLMOVE",
            "BRPOPLPUSH",
            "BLMPOP",
            "BZPOPMIN",
            "BZPOPMAX",
            "BZMPOP",
            "WAIT",
            "WAITAOF",
            "SCRIPT",
            "FUNCTION",
        ] {
            assert_denied(&identity, json!([name]));
        }
        assert_denied(&identity, json!(["CONFIG", "GET", "maxmemory"]));
        assert_denied(&identity, json!(["MEMORY", "USAGE", "key"]));
    }

    #[test]
    fn transaction_state_commands_cannot_escape_onto_a_pooled_connection() {
        let ordinary = identity();
        let mut admin = identity();
        admin.is_admin = true;
        for identity in [&ordinary, &admin] {
            for name in ["MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH"] {
                assert_denied(identity, json!([name]));
            }
        }
    }

    #[test]
    fn command_names_are_normalized_before_every_policy_layer() {
        let mut identity = identity();
        identity.blocked_commands.insert("SET".to_owned());
        identity.allowed_commands = Some(HashSet::from([
            "GET".to_owned(),
            "SET".to_owned(),
            "EVAL".to_owned(),
        ]));
        for command in [
            json!(["config", "get", "maxmemory"]),
            json!(["flushall"]),
            json!(["subscribe", "channel"]),
            json!(["set", "key", "value"]),
            json!(["eval", "return 1", 0]),
        ] {
            assert_denied(&identity, command);
        }
        check(&identity, &parsed(&json!(["get", "key"]))).unwrap();
    }

    #[test]
    fn admin_allowlist_is_subcommand_aware_and_remains_a_gate() {
        let mut admin = identity();
        admin.is_admin = true;
        for command in [
            json!(["CONFIG", "GET", "maxmemory"]),
            json!(["CLIENT", "LIST"]),
            json!(["MEMORY", "USAGE", "key"]),
            json!(["INFO"]),
        ] {
            check(&admin, &parsed(&command)).unwrap();
        }
        for command in [
            json!(["HELLO", 2]),
            json!(["CONFIG", "SET", "x", "y"]),
            json!(["MODULE", "LOAD", "x"]),
            json!(["MIGRATE"]),
            json!(["SLAVEOF"]),
            json!(["CLIENT", "KILL"]),
        ] {
            assert_denied(&admin, command);
        }
        admin.blocked_commands.insert("CONFIG".to_owned());
        assert_denied(&admin, json!(["CONFIG", "GET", "maxmemory"]));
    }

    #[test]
    fn default_blocks_apply_only_to_current_format_identities() {
        let mut current = identity();
        for name in ["FLUSHALL", "FLUSHDB", "KEYS", "RANDOMKEY", "INFO", "DBSIZE"] {
            assert_denied(&current, json!([name]));
        }
        check(&current, &parsed(&json!(["SCAN", 0]))).unwrap();
        current.allowed_commands = Some(HashSet::from(["KEYS".to_owned()]));
        check(&current, &parsed(&json!(["KEYS", "*"]))).unwrap();

        let mut legacy = identity();
        legacy.legacy = true;
        check(&legacy, &parsed(&json!(["FLUSHALL"]))).unwrap();
        check(&legacy, &parsed(&json!(["KEYS", "*"]))).unwrap();
        check(&legacy, &parsed(&json!(["DBSIZE"]))).unwrap();
        check(&legacy, &parsed(&json!(["INFO"]))).unwrap();
    }

    #[test]
    fn explicit_command_allowlist_rejects_every_command_not_named() {
        let mut identity = identity();
        identity.allowed_commands = Some(HashSet::from(["GET".to_owned()]));
        check(&identity, &parsed(&json!(["GET", "key"]))).unwrap();
        assert_denied(&identity, json!(["MGET", "one", "two"]));
    }

    #[test]
    fn script_allowlist_is_a_gate_not_a_grant() {
        let script = "return redis.call('GET', KEYS[1])";
        let digest = hex_digest(&Sha256::digest(script.as_bytes()));
        let mut identity = identity();
        identity.allowed_script_sha256.insert(digest);
        identity.allowed_commands = Some(HashSet::from(["EVAL".to_owned()]));
        check(&identity, &parsed(&json!(["EVAL", script, 1, "key"]))).unwrap();

        identity.read_only = true;
        assert_denied(&identity, json!(["EVAL", script, 1, "key"]));
        identity.read_only = false;
        identity.allowed_commands = Some(HashSet::from(["GET".to_owned(), "SET".to_owned()]));
        assert_denied(&identity, json!(["EVAL", script, 1, "key"]));

        identity.allowed_commands = Some(HashSet::from(["EVAL".to_owned()]));
        assert_denied(&identity, json!(["EVAL", "return 1", 0]));

        identity.allowed_commands = Some(HashSet::from(["EVALSHA".to_owned()]));
        assert_denied(&identity, json!(["EVALSHA", script, 0]));
    }

    #[test]
    fn argument_guards_reject_blocking_xread_and_indirect_sort_keys() {
        let mut identity = identity();
        identity.read_only = true;
        check(&identity, &parsed(&json!(["XREAD", "STREAMS", "key", "0"]))).unwrap();
        assert_eq!(
            check(&identity, &parsed(&json!(["XREAD", "BLOCK", 0]))),
            Err(AclError::Forbidden(
                "NOPERM blocking XREAD is not allowed".to_owned()
            ))
        );
        assert_eq!(
            check(&identity, &parsed(&json!(["XREAD", "block", 0]))),
            Err(AclError::Forbidden(
                "NOPERM blocking XREAD is not allowed".to_owned()
            ))
        );
        identity.key_prefix = Some("tenant:".to_owned());
        assert_denied(
            &identity,
            json!(["SORT_RO", "tenant:list", "BY", "other:*"]),
        );
        assert_denied(
            &identity,
            json!(["SORT_RO", "tenant:list", "GET", "other:*"]),
        );
    }
}
