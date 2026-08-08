use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use bytes::Bytes;

/// Authenticated permissions and routing information.
#[derive(Clone, Debug, Eq, PartialEq)]
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

string_error!(AuthError);
string_error!(JwksError);
string_error!(IntrospectError);
