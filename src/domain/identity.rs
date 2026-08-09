use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use bytes::Bytes;

/// Authenticated permissions and routing information.
#[derive(Clone, Eq, PartialEq)]
pub struct Identity {
    pub subject: String,
    pub bucket_key: String,
    pub pool: String,
    pub read_only: bool,
    pub is_admin: bool,
    pub legacy: bool,
    pub allowed_commands: Option<HashSet<String>>,
    pub blocked_commands: HashSet<String>,
    pub allowed_script_sha256: HashSet<String>,
    pub key_prefix: Option<String>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("subject", &self.subject)
            .field("bucket_key", &"<redacted>")
            .field("pool", &self.pool)
            .field("read_only", &self.read_only)
            .field("is_admin", &self.is_admin)
            .field("legacy", &self.legacy)
            .field("allowed_commands", &self.allowed_commands)
            .field("blocked_commands", &self.blocked_commands)
            .field("allowed_script_sha256", &self.allowed_script_sha256)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

/// A JWT verification algorithm selected from trusted JWK metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtAlgorithm {
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
}

/// Trusted verification-key material cached by a JWKS source.
///
/// The representation remains independent of the JWT adapter library so the
/// domain and ports do not expose `jsonwebtoken` types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedKey {
    pub algorithm: JwtAlgorithm,
    pub material: Bytes,
}

macro_rules! string_error {
    ($name:ident) => {
        /// Adapter-facing error text. Callers must never include bearer tokens or
        /// other credential material in this message.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name(pub String);

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Error for $name {}
    };
}

/// A definitive authentication failure or a dependency outage.
///
/// Unrecognized credential formats are represented by `Ok(None)` at the port,
/// not by an error. Error details must never contain credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    Rejected,
    Forbidden(String),
    ServiceUnavailable(String),
}

impl Display for AuthError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => formatter.write_str("authentication rejected"),
            Self::Forbidden(message) | Self::ServiceUnavailable(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for AuthError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JwksError {
    NotFound,
    Unavailable(String),
}

impl Display for JwksError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("no matching signing key"),
            Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl Error for JwksError {}

string_error!(IntrospectError);
