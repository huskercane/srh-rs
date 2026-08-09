use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request};
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::domain::identity::{CachedKey, JwksError, JwtAlgorithm};
use crate::ports::JwksSource;

use super::outbound_http::{HttpClient, build_client, request_bytes};

const DISCOVERY_LIMIT: usize = 64 * 1024;
const JWKS_LIMIT: usize = 1024 * 1024;
const FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
    jwks_uri: Option<String>,
    last_forced_refresh: Option<Instant>,
}

/// Hyper/rustls-backed OpenID discovery and JWKS adapter.
pub struct HttpJwks {
    issuer: String,
    refresh_after: Duration,
    client: HttpClient,
    cache: RwLock<KeyCache>,
    refresh_lock: Mutex<()>,
}

impl HttpJwks {
    /// Creates a lazy JWKS source using native trust roots and the ring provider.
    pub fn new(issuer: String, refresh_secs: u64) -> Result<Self, JwksError> {
        Ok(Self {
            issuer,
            refresh_after: Duration::from_secs(refresh_secs),
            client: build_client().map_err(JwksError::Unavailable)?,
            cache: RwLock::new(KeyCache::default()),
            refresh_lock: Mutex::new(()),
        })
    }

    async fn refresh_if_needed(&self) -> Result<(), JwksError> {
        let stale = {
            let cache = self.cache.read().await;
            cache
                .fetched_at
                .is_none_or(|fetched| fetched.elapsed() >= self.refresh_after)
        };
        if stale {
            self.refresh(false).await?;
        }
        Ok(())
    }

    async fn refresh(&self, forced: bool) -> Result<(), JwksError> {
        let _guard = self.refresh_lock.lock().await;
        let now = Instant::now();
        {
            let cache = self.cache.read().await;
            if forced {
                if cache.last_forced_refresh.is_some_and(|last| {
                    now.saturating_duration_since(last) < FORCED_REFRESH_INTERVAL
                }) {
                    return Ok(());
                }
            } else if cache
                .fetched_at
                .is_some_and(|fetched| now.saturating_duration_since(fetched) < self.refresh_after)
            {
                return Ok(());
            }
        }
        if forced {
            // Record admission before I/O so a failing JWKS endpoint cannot turn repeated
            // attacker-controlled kids into an unbounded forced-refresh loop.
            self.cache.write().await.last_forced_refresh = Some(now);
        }

        let jwks_uri = match self.cache.read().await.jwks_uri.clone() {
            Some(uri) => uri,
            None => self.fetch_discovery().await?,
        };
        let keys = self.fetch_keys(&jwks_uri).await?;
        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(now);
        cache.jwks_uri = Some(jwks_uri);
        Ok(())
    }

    async fn fetch_discovery(&self) -> Result<String, JwksError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let body = self.get(&url, DISCOVERY_LIMIT).await?;
        let discovery: Discovery = serde_json::from_slice(&body).map_err(|error| {
            JwksError::Unavailable(format!("invalid OpenID discovery document: {error}"))
        })?;
        validate_http_url(&discovery.jwks_uri)?;
        Ok(discovery.jwks_uri)
    }

    async fn fetch_keys(&self, url: &str) -> Result<HashMap<String, CachedKey>, JwksError> {
        let body = self.get(url, JWKS_LIMIT).await?;
        let set: JwkSet = serde_json::from_slice(&body)
            .map_err(|error| JwksError::Unavailable(format!("invalid JWKS document: {error}")))?;
        Ok(set.keys.into_iter().filter_map(cacheable_key).collect())
    }

    async fn get(&self, url: &str, limit: usize) -> Result<Bytes, JwksError> {
        validate_http_url(url)?;
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Full::new(Bytes::new()))
            .map_err(|error| {
                JwksError::Unavailable(format!("invalid outbound HTTP request: {error}"))
            })?;
        request_bytes(&self.client, request, limit)
            .await
            .map_err(JwksError::Unavailable)
    }
}

#[async_trait]
impl JwksSource for HttpJwks {
    async fn key_for(&self, kid: &str) -> Result<CachedKey, JwksError> {
        self.refresh_if_needed().await?;
        if let Some(key) = self.cache.read().await.keys.get(kid).cloned() {
            return Ok(key);
        }
        self.refresh(true).await?;
        self.cache
            .read()
            .await
            .keys
            .get(kid)
            .cloned()
            .ok_or(JwksError::NotFound)
    }
}

fn cacheable_key(jwk: Jwk) -> Option<(String, CachedKey)> {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| !matches!(usage, PublicKeyUse::Signature))
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return None;
    }
    let kid = jwk.common.key_id.clone()?;
    let algorithm = match (&jwk.algorithm, jwk.common.key_algorithm) {
        (AlgorithmParameters::RSA(_), None | Some(KeyAlgorithm::RS256)) => JwtAlgorithm::Rs256,
        (AlgorithmParameters::RSA(_), Some(KeyAlgorithm::RS384)) => JwtAlgorithm::Rs384,
        (AlgorithmParameters::RSA(_), Some(KeyAlgorithm::RS512)) => JwtAlgorithm::Rs512,
        (AlgorithmParameters::EllipticCurve(parameters), None) => match parameters.curve {
            EllipticCurve::P256 => JwtAlgorithm::Es256,
            EllipticCurve::P384 => JwtAlgorithm::Es384,
            _ => return None,
        },
        (AlgorithmParameters::EllipticCurve(parameters), Some(KeyAlgorithm::ES256))
            if parameters.curve == EllipticCurve::P256 =>
        {
            JwtAlgorithm::Es256
        }
        (AlgorithmParameters::EllipticCurve(parameters), Some(KeyAlgorithm::ES384))
            if parameters.curve == EllipticCurve::P384 =>
        {
            JwtAlgorithm::Es384
        }
        _ => return None,
    };
    let material = serde_json::to_vec(&jwk).ok()?;
    Some((
        kid,
        CachedKey {
            algorithm,
            material: Bytes::from(material),
        },
    ))
}

fn validate_http_url(value: &str) -> Result<(), JwksError> {
    let url = url::Url::parse(value)
        .map_err(|error| JwksError::Unavailable(format!("invalid outbound URL: {error}")))?;
    if matches!(url.scheme(), "http" | "https") {
        Ok(())
    } else {
        Err(JwksError::Unavailable(
            "outbound URL must use http or https".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn rsa(kid: &str, extra: serde_json::Value) -> Jwk {
        let mut value = json!({
            "kty":"RSA", "kid":kid, "n":"AQAB", "e":"AQAB"
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn filters_non_signing_keys_and_derives_only_supported_algorithms() {
        assert!(cacheable_key(rsa("enc", json!({"use":"enc","alg":"RS256"}))).is_none());
        assert!(cacheable_key(rsa("sign-only", json!({"key_ops":["sign"]}))).is_none());
        assert!(cacheable_key(rsa("oaep", json!({"alg":"RSA-OAEP"}))).is_none());
        assert_eq!(
            cacheable_key(rsa("default", json!({})))
                .unwrap()
                .1
                .algorithm,
            JwtAlgorithm::Rs256
        );
        let ec: Jwk = serde_json::from_value(json!({
            "kty":"EC", "kid":"ec", "crv":"P-384", "x":"AQ", "y":"AQ",
            "use":"sig"
        }))
        .unwrap();
        assert_eq!(cacheable_key(ec).unwrap().1.algorithm, JwtAlgorithm::Es384);
    }

    #[tokio::test]
    async fn unknown_kid_forces_one_throttled_refetch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jwks_uri":format!("{}/keys", server.uri())
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys":[{"kty":"RSA","kid":"known","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]
            })))
            .mount(&server)
            .await;

        let jwks = HttpJwks::new(server.uri(), 600).unwrap();
        assert!(jwks.key_for("missing-one").await.is_err());
        assert!(jwks.key_for("missing-two").await.is_err());

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/.well-known/openid-configuration")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/keys")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn redirects_and_oversized_responses_are_rejected() {
        let server = MockServer::start().await;
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/next", server.uri())),
            )
            .mount(&server)
            .await;
        let jwks = HttpJwks::new(server.uri(), 600).unwrap();
        assert!(
            jwks.key_for("kid")
                .await
                .unwrap_err()
                .to_string()
                .contains("redirects")
        );

        let oversized = MockServer::start().await;
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jwks_uri":format!("{}/keys", oversized.uri()),
                "padding":"x".repeat(DISCOVERY_LIMIT)
            })))
            .mount(&oversized)
            .await;
        Mock::given(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]
            })))
            .mount(&oversized)
            .await;
        let jwks = HttpJwks::new(oversized.uri(), 600).unwrap();
        assert!(jwks.key_for("kid").await.is_err());
    }
}
