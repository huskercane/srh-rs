use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::{JwtConfig, PoolConfig};
use crate::domain::identity::{AuthError, Identity, JwtAlgorithm};
use crate::ports::{Authenticator, Clock, Introspector, JwksSource};

const MAX_INTROSPECTION_ENTRIES: usize = 100_000;
const CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    aud: Audience,
    #[serde(default)]
    azp: Option<String>,
    typ: String,
    #[serde(default)]
    resource_access: HashMap<String, ClientAccess>,
    #[serde(default)]
    srh_pool: Option<String>,
    #[serde(default)]
    srh_blocked_commands: Vec<String>,
    #[serde(default)]
    srh_key_prefix: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    Missing,
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
            Self::Missing => false,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct ClientAccess {
    #[serde(default)]
    roles: Vec<String>,
}

struct CacheEntry {
    active: bool,
    expires_at: Instant,
    last_access: Instant,
    order: u64,
}

#[derive(Default)]
struct IntrospectionEntries {
    entries: HashMap<[u8; 32], CacheEntry>,
    lru: BTreeSet<(Instant, u64, [u8; 32])>,
    next_order: u64,
}

struct IntrospectionCache {
    ttl_secs: u64,
    clock: Arc<dyn Clock>,
    max_entries: usize,
    entries: Mutex<IntrospectionEntries>,
}

impl IntrospectionCache {
    fn new(ttl_secs: u64, clock: Arc<dyn Clock>) -> Self {
        Self {
            ttl_secs,
            clock,
            max_entries: MAX_INTROSPECTION_ENTRIES,
            entries: Mutex::new(IntrospectionEntries::default()),
        }
    }

    #[cfg(test)]
    fn with_max_entries(ttl_secs: u64, clock: Arc<dyn Clock>, max_entries: usize) -> Self {
        Self {
            ttl_secs,
            clock,
            max_entries: max_entries.max(1),
            entries: Mutex::new(IntrospectionEntries::default()),
        }
    }

    fn get(&self, digest: &[u8; 32]) -> Option<bool> {
        let now = self.clock.instant();
        let mut state = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entry = state.entries.remove(digest)?;
        state.lru.remove(&(entry.last_access, entry.order, *digest));
        if now >= entry.expires_at {
            return None;
        }
        entry.last_access = now;
        entry.order = state.next_order;
        state.next_order = state.next_order.wrapping_add(1);
        state.lru.insert((entry.last_access, entry.order, *digest));
        let active = entry.active;
        state.entries.insert(*digest, entry);
        Some(active)
    }

    fn insert(&self, digest: [u8; 32], active: bool) {
        let now = self.clock.instant();
        let mut state = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = state.entries.remove(&digest) {
            state
                .lru
                .remove(&(previous.last_access, previous.order, digest));
        } else if state.entries.len() >= self.max_entries
            && let Some((_, _, oldest)) = state.lru.pop_first()
        {
            state.entries.remove(&oldest);
        }
        let order = state.next_order;
        state.next_order = state.next_order.wrapping_add(1);
        let entry = CacheEntry {
            active,
            expires_at: now + std::time::Duration::from_secs(self.ttl_secs),
            last_access: now,
            order,
        };
        state.lru.insert((now, order, digest));
        state.entries.insert(digest, entry);
    }

    fn sweep(&self) -> usize {
        let now = self.clock.instant();
        let mut state = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired = state
            .entries
            .iter()
            .filter_map(|(digest, entry)| (now >= entry.expires_at).then_some(*digest))
            .collect::<Vec<_>>();
        for digest in &expired {
            if let Some(entry) = state.entries.remove(digest) {
                state.lru.remove(&(entry.last_access, entry.order, *digest));
            }
        }
        expired.len()
    }
}

/// Validates Keycloak access tokens using trusted keys supplied through a port.
pub struct JwtAuth {
    config: JwtConfig,
    pools: HashMap<String, HashSet<String>>,
    jwks: Arc<dyn JwksSource>,
    introspector: Option<Arc<dyn Introspector>>,
    introspection_cache: IntrospectionCache,
}

impl JwtAuth {
    /// Creates a JWT authenticator from normalized policy and its outbound ports.
    pub fn new(
        config: JwtConfig,
        pools: &HashMap<String, PoolConfig>,
        jwks: Arc<dyn JwksSource>,
        introspector: Option<Arc<dyn Introspector>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let scripts = pools
            .iter()
            .map(|(name, pool)| (name.clone(), pool.allowed_script_sha256.clone()))
            .collect();
        let cache_secs = config.introspection.cache_secs;
        Self {
            config,
            pools: scripts,
            jwks,
            introspector,
            introspection_cache: IntrospectionCache::new(cache_secs, clock),
        }
    }

    /// Removes expired introspection results during the shared maintenance pass.
    pub fn sweep_introspection_cache(&self) -> usize {
        self.introspection_cache.sweep()
    }

    async fn validate(&self, bearer: &str) -> Result<Identity, AuthError> {
        let header = decode_header(bearer).map_err(|_| AuthError::Rejected)?;
        let kid = header.kid.ok_or(AuthError::Rejected)?;
        let cached = self.jwks.key_for(&kid).await.map_err(|error| match error {
            crate::domain::identity::JwksError::NotFound => AuthError::Rejected,
            crate::domain::identity::JwksError::Unavailable(reason) => {
                AuthError::ServiceUnavailable(reason)
            }
        })?;
        let algorithm = algorithm(cached.algorithm);
        let jwk = serde_json::from_slice(&cached.material).map_err(|_| AuthError::Rejected)?;
        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|_| AuthError::Rejected)?;
        let mut validation = Validation::new(algorithm);
        validation.leeway = CLOCK_SKEW_SECS;
        validation.validate_nbf = true;
        // Keycloak commonly expresses the authorized party through `azp` instead of `aud`,
        // so audience is checked below after all cryptographic validation succeeds.
        validation.validate_aud = false;
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        let claims = decode::<Claims>(bearer, &decoding_key, &validation)
            .map_err(|_| AuthError::Rejected)?
            .claims;
        if claims.typ != "Bearer"
            || (!claims.aud.contains(&self.config.audience)
                && claims.azp.as_deref() != Some(self.config.audience.as_str()))
        {
            return Err(AuthError::Rejected);
        }

        if let Some(introspector) = &self.introspector {
            let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
            let active = if let Some(active) = self.introspection_cache.get(&digest) {
                active
            } else {
                let active = introspector
                    .is_active(bearer)
                    .await
                    .map_err(|error| AuthError::ServiceUnavailable(error.to_string()))?;
                self.introspection_cache.insert(digest, active);
                active
            };
            if !active {
                return Err(AuthError::Rejected);
            }
        }

        self.identity(claims)
    }

    fn identity(&self, claims: Claims) -> Result<Identity, AuthError> {
        let roles = claims
            .resource_access
            .get(&self.config.client_id)
            .map(|access| access.roles.as_slice())
            .unwrap_or_default();
        let role = |name: &str| {
            let expected = format!("{}{name}", self.config.role_prefix);
            roles.iter().any(|candidate| candidate == &expected)
        };
        let (read_only, is_admin) = if role("admin") {
            (false, true)
        } else if role("write") {
            (false, false)
        } else if role("read") {
            (true, false)
        } else {
            return Err(AuthError::Forbidden("NOPERM no redis role".to_owned()));
        };
        let pool = claims.srh_pool.unwrap_or_else(|| "default".to_owned());
        let Some(allowed_script_sha256) = self.pools.get(&pool) else {
            return Err(AuthError::Forbidden("NOPERM invalid redis pool".to_owned()));
        };
        Ok(Identity {
            subject: claims.sub.clone(),
            bucket_key: claims.sub,
            pool,
            read_only,
            is_admin,
            legacy: false,
            allowed_commands: None,
            blocked_commands: claims
                .srh_blocked_commands
                .into_iter()
                .map(|command| command.to_ascii_uppercase())
                .collect(),
            allowed_script_sha256: allowed_script_sha256.clone(),
            key_prefix: claims.srh_key_prefix,
        })
    }
}

#[async_trait]
impl Authenticator for JwtAuth {
    async fn authenticate(&self, bearer: &str) -> Result<Option<Identity>, AuthError> {
        if bearer.bytes().filter(|byte| *byte == b'.').count() != 2 {
            return Ok(None);
        }
        self.validate(bearer).await.map(Some)
    }
}

fn algorithm(value: JwtAlgorithm) -> Algorithm {
    match value {
        JwtAlgorithm::Rs256 => Algorithm::RS256,
        JwtAlgorithm::Rs384 => Algorithm::RS384,
        JwtAlgorithm::Rs512 => Algorithm::RS512,
        JwtAlgorithm::Es256 => Algorithm::ES256,
        JwtAlgorithm::Es384 => Algorithm::ES384,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use base64::Engine;
    use bytes::Bytes;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use super::*;
    use crate::adapters::system_clock::SystemClock;
    use crate::config::Config;
    use crate::domain::identity::{CachedKey, IntrospectError};
    use crate::testsupport::FakeJwks;

    const PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;
    const MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";

    fn config() -> Config {
        Config::from_json(
            r#"{
                "auth":{"jwt":{"issuer":"https://issuer.test/realms/test","audience":"srh","client_id":"srh"}},
                "pools":{"default":{"connection_string":"redis://localhost:6379","allowed_script_sha256":["abcd"]}}
            }"#,
        )
        .unwrap()
    }

    fn key(algorithm: JwtAlgorithm) -> CachedKey {
        CachedKey {
            algorithm,
            material: Bytes::from(
                serde_json::to_vec(&json!({
                    "kty":"RSA", "kid":"test-key", "use":"sig", "alg":"RS256",
                    "n":MODULUS, "e":"AQAB"
                }))
                .unwrap(),
            ),
        }
    }

    fn claims() -> Value {
        let now = jsonwebtoken::get_current_timestamp();
        json!({
            "sub":"user-123", "iss":"https://issuer.test/realms/test",
            "exp":now + 300, "nbf":now - 1, "aud":["srh"], "typ":"Bearer",
            "resource_access":{"srh":{"roles":["redis:write"]}},
            "srh_blocked_commands":["client"], "srh_key_prefix":"tenant:"
        })
    }

    fn token(claims: &Value, algorithm: Algorithm) -> String {
        let mut header = Header::new(algorithm);
        header.kid = Some("test-key".to_owned());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn auth(key_algorithm: JwtAlgorithm) -> JwtAuth {
        let config = config();
        let jwt = config.auth.jwt.clone().unwrap();
        let jwks = FakeJwks::new(HashMap::from([("test-key".to_owned(), key(key_algorithm))]));
        JwtAuth::new(
            jwt,
            &config.pools,
            Arc::new(jwks),
            None,
            Arc::new(SystemClock),
        )
    }

    #[tokio::test]
    async fn valid_write_token_maps_claims_and_pool_policy() {
        let identity = auth(JwtAlgorithm::Rs256)
            .authenticate(&token(&claims(), Algorithm::RS256))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.subject, "user-123");
        assert_eq!(identity.bucket_key, "user-123");
        assert_eq!(identity.pool, "default");
        assert!(!identity.read_only);
        assert!(identity.blocked_commands.contains("CLIENT"));
        assert!(identity.allowed_script_sha256.contains("abcd"));
        assert_eq!(identity.key_prefix.as_deref(), Some("tenant:"));
    }

    #[tokio::test]
    async fn validation_rejects_untrusted_algorithms_and_security_claims() {
        let auth = auth(JwtAlgorithm::Rs256);
        let mut cases = Vec::new();
        cases.push(token(&claims(), Algorithm::RS384));
        let mut hs_header = Header::new(Algorithm::HS256);
        hs_header.kid = Some("test-key".to_owned());
        cases.push(
            encode(
                &hs_header,
                &claims(),
                &EncodingKey::from_secret(b"attacker-controlled-secret"),
            )
            .unwrap(),
        );
        let none_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","kid":"test-key"}"#);
        let none_claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims()).unwrap());
        cases.push(format!("{none_header}.{none_claims}."));
        for (field, value) in [
            ("iss", json!("https://wrong.test")),
            ("aud", json!(["wrong"])),
            ("typ", json!("ID")),
            ("exp", json!(1)),
            ("nbf", json!(jsonwebtoken::get_current_timestamp() + 300)),
        ] {
            let mut candidate = claims();
            candidate[field] = value;
            cases.push(token(&candidate, Algorithm::RS256));
        }
        for candidate in cases {
            assert_eq!(
                auth.authenticate(&candidate).await,
                Err(AuthError::Rejected)
            );
        }
        assert_eq!(auth.authenticate("not-a-static-token").await.unwrap(), None);
    }

    #[tokio::test]
    async fn azp_is_an_audience_fallback_and_missing_role_is_forbidden() {
        let auth = auth(JwtAlgorithm::Rs256);
        let mut candidate = claims();
        candidate["aud"] = json!(["account"]);
        candidate["azp"] = json!("srh");
        assert!(
            auth.authenticate(&token(&candidate, Algorithm::RS256))
                .await
                .unwrap()
                .is_some()
        );

        candidate["resource_access"] = json!({"srh":{"roles":[]}});
        assert_eq!(
            auth.authenticate(&token(&candidate, Algorithm::RS256))
                .await,
            Err(AuthError::Forbidden("NOPERM no redis role".to_owned()))
        );

        candidate["resource_access"] = json!({"srh":{"roles":["redis:admin"]}});
        let admin = auth
            .authenticate(&token(&candidate, Algorithm::RS256))
            .await
            .unwrap()
            .unwrap();
        assert!(admin.is_admin);
        assert!(!admin.read_only);
    }

    struct Down;

    #[async_trait]
    impl Introspector for Down {
        async fn is_active(&self, _token: &str) -> Result<bool, IntrospectError> {
            Err(IntrospectError("introspection unavailable".to_owned()))
        }
    }

    #[tokio::test]
    async fn introspection_dependency_failure_is_service_unavailable() {
        let config = config();
        let jwt = config.auth.jwt.clone().unwrap();
        let jwks = FakeJwks::new(HashMap::from([(
            "test-key".to_owned(),
            key(JwtAlgorithm::Rs256),
        )]));
        let auth = JwtAuth::new(
            jwt,
            &config.pools,
            Arc::new(jwks),
            Some(Arc::new(Down)),
            Arc::new(SystemClock),
        );
        assert_eq!(
            auth.authenticate(&token(&claims(), Algorithm::RS256)).await,
            Err(AuthError::ServiceUnavailable(
                "introspection unavailable".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn unknown_kid_is_a_definitive_rejection() {
        let config = config();
        let jwt = config.auth.jwt.clone().unwrap();
        let auth = JwtAuth::new(
            jwt,
            &config.pools,
            Arc::new(FakeJwks::default()),
            None,
            Arc::new(SystemClock),
        );
        assert_eq!(
            auth.authenticate(&token(&claims(), Algorithm::RS256)).await,
            Err(AuthError::Rejected)
        );
    }

    struct ManualClock {
        base: Instant,
        seconds: AtomicU64,
    }

    impl ManualClock {
        fn advance(&self, seconds: u64) {
            self.seconds.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn unix_secs(&self) -> u64 {
            0
        }

        fn instant(&self) -> Instant {
            self.base + Duration::from_secs(self.seconds.load(Ordering::Relaxed))
        }
    }

    #[test]
    fn introspection_cache_is_ttl_swept_bounded_and_lru_evicted() {
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            seconds: AtomicU64::new(0),
        });
        let clock_port: Arc<dyn Clock> = clock.clone();
        assert_eq!(MAX_INTROSPECTION_ENTRIES, 100_000);
        let cache = IntrospectionCache::with_max_entries(30, clock_port, 2);
        for index in 0..2_usize {
            cache.insert(Sha256::digest(index.to_le_bytes()).into(), true);
        }
        let oldest: [u8; 32] = Sha256::digest(0_usize.to_le_bytes()).into();
        let next_oldest: [u8; 32] = Sha256::digest(1_usize.to_le_bytes()).into();
        assert_eq!(cache.get(&oldest), Some(true));
        cache.insert(Sha256::digest(b"one-over-the-bound").into(), false);
        let state = cache
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.entries.len(), 2);
        assert!(state.entries.contains_key(&oldest));
        assert!(!state.entries.contains_key(&next_oldest));
        drop(state);

        clock.advance(31);
        assert_eq!(cache.sweep(), 2);
    }
}
