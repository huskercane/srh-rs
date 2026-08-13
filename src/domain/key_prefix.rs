use std::error::Error;
use std::fmt::{self, Display, Formatter};

const MAX_PREFIX_BYTES: usize = 128;

/// A key-prefix value that cannot safely narrow a pool's keyspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrefixError {
    Empty,
    TooLong(usize),
    IllegalByte(u8),
    NotUnderFloor,
}

impl Display for PrefixError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("key prefix must not be empty"),
            Self::TooLong(length) => write!(
                formatter,
                "key prefix is {length} bytes; maximum is {MAX_PREFIX_BYTES}"
            ),
            Self::IllegalByte(byte) => {
                write!(formatter, "key prefix contains illegal byte 0x{byte:02x}")
            }
            Self::NotUnderFloor => {
                formatter.write_str("key prefix does not extend the pool key-prefix floor")
            }
        }
    }
}

impl Error for PrefixError {}

/// Validates a configured or claimed key prefix in isolation.
pub fn validate(prefix: &str) -> Result<(), PrefixError> {
    if prefix.is_empty() {
        return Err(PrefixError::Empty);
    }
    if prefix.len() > MAX_PREFIX_BYTES {
        return Err(PrefixError::TooLong(prefix.len()));
    }
    if let Some(byte) = prefix.bytes().find(|byte| {
        byte.is_ascii_control()
            || *byte == b' '
            || matches!(*byte, b'*' | b'?' | b'[' | b']' | b'\\')
    }) {
        return Err(PrefixError::IllegalByte(byte));
    }
    Ok(())
}

/// Resolves a server-controlled floor and credential candidate into the effective prefix.
pub fn resolve(
    floor: Option<&str>,
    candidate: Option<&str>,
) -> Result<Option<String>, PrefixError> {
    if let Some(floor) = floor {
        validate(floor)?;
    }
    if let Some(candidate) = candidate {
        validate(candidate)?;
    }
    match (floor, candidate) {
        (None, None) => Ok(None),
        (None, Some(candidate)) => Ok(Some(candidate.to_owned())),
        (Some(floor), None) => Ok(Some(floor.to_owned())),
        (Some(floor), Some(candidate)) if candidate.starts_with(floor) => {
            Ok(Some(candidate.to_owned()))
        }
        (Some(_), Some(_)) => Err(PrefixError::NotUnderFloor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_every_floor_and_candidate_combination() {
        assert_eq!(resolve(None, None), Ok(None));
        assert_eq!(
            resolve(None, Some("tenant:")),
            Ok(Some("tenant:".to_owned()))
        );
        assert_eq!(
            resolve(Some("tenant:"), None),
            Ok(Some("tenant:".to_owned()))
        );
        assert_eq!(
            resolve(Some("tenant:"), Some("tenant:user:")),
            Ok(Some("tenant:user:".to_owned()))
        );
        assert_eq!(
            resolve(Some("tenant:"), Some("tenant:")),
            Ok(Some("tenant:".to_owned()))
        );
        assert_eq!(
            resolve(Some("tenant:"), Some("other:")),
            Err(PrefixError::NotUnderFloor)
        );
    }

    #[test]
    fn rejects_empty_and_oversized_values_from_either_source() {
        assert_eq!(resolve(Some(""), None), Err(PrefixError::Empty));
        assert_eq!(resolve(None, Some("")), Err(PrefixError::Empty));
        assert_eq!(validate(&"a".repeat(128)), Ok(()));
        assert_eq!(validate(&"a".repeat(129)), Err(PrefixError::TooLong(129)));
        assert_eq!(validate(&"é".repeat(64)), Ok(()));
        assert_eq!(validate(&"é".repeat(65)), Err(PrefixError::TooLong(130)));
    }

    #[test]
    fn rejects_acl_metacharacters_space_and_control_bytes() {
        for (prefix, byte) in [
            ("tenant:*", b'*'),
            ("tenant:?", b'?'),
            ("tenant:[", b'['),
            ("tenant:]", b']'),
            ("tenant:\\", b'\\'),
            ("tenant root:", b' '),
            ("tenant:\n", b'\n'),
            ("tenant:\u{7f}", 0x7f),
        ] {
            assert_eq!(validate(prefix), Err(PrefixError::IllegalByte(byte)));
        }
    }
}
