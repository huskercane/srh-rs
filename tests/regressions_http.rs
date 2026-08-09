//! Regression locks for defects found by review that need no Redis.
//!
//! Each test in this file asserts the corrected behavior for a defect found by review.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::json;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::jwt_auth::JwtAuth;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::compat::normalize;
use srh_rs::domain::identity::{CachedKey, JwksError};
use srh_rs::ports::{Authenticator, Clock, JwksSource, RedisCommand};

struct FixedClock;

impl Clock for FixedClock {
    fn unix_secs(&self) -> u64 {
        0
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}

/// A JWKS that trusts nothing, so only the token-shape decision is under test.
struct NoTrustedKeys;

#[async_trait]
impl JwksSource for NoTrustedKeys {
    async fn key_for(&self, _kid: &str) -> Result<CachedKey, JwksError> {
        Err(JwksError::NotFound)
    }
}

fn chain_with_jwt_enabled(static_token: &str) -> AuthChain {
    let config = Config::from_json(
        &json!({
            "auth": {
                "jwt": {
                    "issuer": "https://issuer.test/realms/test",
                    "audience": "srh",
                    "client_id": "srh"
                },
                "static_tokens": { static_token: { "pool": "default" } }
            },
            "pools": { "default": { "connection_string": "redis://localhost:6379" } }
        })
        .to_string(),
    )
    .expect("config with a JWT issuer and one static token should parse");
    let jwt: Arc<dyn Authenticator> = Arc::new(JwtAuth::new(
        config.auth.jwt.clone().expect("JWT auth is configured"),
        &config.pools,
        Arc::new(NoTrustedKeys),
        None,
        Arc::new(FixedClock),
    ));
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    AuthChain::new(vec![jwt, static_auth])
}

/// `JwtAuth` claims any bearer containing exactly two dots and returns a definitive `Err` when
/// validation fails, so the chain never reaches `StaticAuth`. A configured static token whose
/// text happens to hold two dots is therefore a permanent 401 once JWT auth is enabled — and
/// nothing at startup says so. That silently disables the documented break-glass token during
/// an IdP outage, which is the one moment it exists for.
///
/// The fix that keeps chain semantics intact: only a `decode_header` failure (structurally not
/// a JWT) may abstain with `Ok(None)`; every failure after the header parse stays `Err`, so a
/// JWT failing signature verification is still never retried as a static token.
#[tokio::test]
async fn a_static_token_containing_two_dots_still_authenticates() {
    for token in ["ops.break.glass", "a.b.c"] {
        let identity = chain_with_jwt_enabled(token)
            .authenticate(token)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "static token {token:?} was rejected with {error:?} instead of falling \
                     through to StaticAuth: JwtAuth claims every two-dot bearer, so this \
                     break-glass token is unusable while JWT auth is enabled"
                )
            });
        assert!(
            identity.is_some(),
            "static token {token:?} should resolve to an identity"
        );
    }
}

/// Successfully decoding a JWT header commits authentication to the JWT link. A bad signature,
/// unknown key, or invalid claim must never fall through to a same-value static credential.
#[tokio::test]
async fn a_structurally_valid_jwt_cannot_fall_through_to_static_auth() {
    for token in [
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1pc3NpbmcifQ.e30.c2lnbmF0dXJl",
        "eyJhbGciOiJub25lIiwia2lkIjoieCJ9.e30.",
    ] {
        assert!(
            chain_with_jwt_enabled(token)
                .authenticate(token)
                .await
                .is_err()
        );
    }
}

/// Once malformed JWT headers abstain, dotted plaintext credentials are reachable through the
/// static link and remain valid configuration.
#[test]
fn config_validation_accepts_a_reachable_dotted_static_token() {
    let result = Config::from_json(
        &json!({
            "auth": {
                "jwt": {
                    "issuer": "https://issuer.test/realms/test",
                    "audience": "srh",
                    "client_id": "srh"
                },
                "static_tokens": { "ops.break.glass": { "pool": "default" } }
            },
            "pools": { "default": { "connection_string": "redis://localhost:6379" } }
        })
        .to_string(),
    );
    assert!(result.is_ok());
}

/// `GEODIST` is `key member1 member2 [unit]`. The unit normalization lowercases the LAST
/// argument unconditionally, so when the optional unit is omitted it rewrites `member2`.
/// Member names are user data and case-sensitive, so `GEODIST k A KM` silently queries member
/// `km` and returns nil instead of a distance. The normalization needs an arity guard.
#[test]
fn geodist_without_a_unit_preserves_the_second_member_name() {
    let command = RedisCommand {
        name: "GEODIST".to_owned(),
        args: ["Sicily", "Palermo", "KM"]
            .into_iter()
            .map(Bytes::from)
            .collect(),
    };
    let normalized = normalize(command);
    assert_eq!(
        normalized.args.last().map(Bytes::as_ref),
        Some(b"KM".as_slice()),
        "three-argument GEODIST has no unit, so the last argument is a member name and must \
         pass through byte-for-byte"
    );
}

/// The four-argument form still needs the unit lowercased, because Redis compares geo units
/// with a case-sensitive `strcmp`. This guards against fixing the arity bug by deleting the
/// normalization outright.
#[test]
fn geodist_with_a_unit_still_lowercases_it() {
    let command = RedisCommand {
        name: "GEODIST".to_owned(),
        args: ["Sicily", "Palermo", "Catania", "KM"]
            .into_iter()
            .map(Bytes::from)
            .collect(),
    };
    let normalized = normalize(command);
    assert_eq!(
        normalized.args.last().map(Bytes::as_ref),
        Some(b"km".as_slice()),
        "four-argument GEODIST ends in the unit, which Redis only accepts in lower case"
    );
}
