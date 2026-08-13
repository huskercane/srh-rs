use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::config::{ConfigError, PoolConfig, StaticTokenConfig, digest_hex};
use crate::domain::identity::{AuthError, Identity};
use crate::domain::key_prefix;
use crate::ports::Authenticator;

pub struct StaticAuth {
    identities: HashMap<[u8; 32], Arc<Identity>>,
}

impl StaticAuth {
    pub fn new(
        tokens: HashMap<[u8; 32], StaticTokenConfig>,
        pools: &HashMap<String, PoolConfig>,
    ) -> Result<Self, ConfigError> {
        let identities = tokens
            .into_iter()
            .map(|(digest, token)| {
                let policy = pools.get(&token.pool).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "static token references missing pool '{}'",
                        token.pool
                    ))
                })?;
                let key_prefix =
                    key_prefix::resolve(policy.key_prefix.as_deref(), token.key_prefix.as_deref())
                        .map_err(|error| {
                            ConfigError::Validation(format!(
                                "static token for pool '{}' has invalid key_prefix: {error}",
                                token.pool
                            ))
                        })?;
                let bucket_key = digest_hex(&digest);
                let identity = Identity {
                    subject: bucket_key[..8].to_owned(),
                    bucket_key,
                    pool: token.pool,
                    read_only: token.read_only,
                    is_admin: false,
                    legacy: token.legacy,
                    allowed_commands: token.allowed_commands,
                    blocked_commands: token.blocked_commands,
                    allowed_script_sha256: token.allowed_script_sha256,
                    key_prefix,
                };
                Ok((digest, Arc::new(identity)))
            })
            .collect::<Result<_, ConfigError>>()?;
        Ok(Self { identities })
    }
}

#[async_trait]
impl Authenticator for StaticAuth {
    async fn authenticate(&self, bearer: &str) -> Result<Option<Arc<Identity>>, AuthError> {
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        Ok(self.identities.get(&digest).map(Arc::clone))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn authenticates_by_digest_without_exposing_bucket_key_in_debug() {
        let digest: [u8; 32] = Sha256::digest(b"secret").into();
        let config = crate::config::Config::from_json(
            r#"{"pools":{"cache":{"connection_string":"redis://localhost:6379","key_prefix":"tenant:"}}}"#,
        )
        .expect("pool config should parse");
        let auth = StaticAuth::new(
            HashMap::from([(
                digest,
                StaticTokenConfig {
                    pool: "cache".to_owned(),
                    read_only: true,
                    legacy: false,
                    allowed_commands: None,
                    blocked_commands: HashSet::new(),
                    allowed_script_sha256: HashSet::new(),
                    key_prefix: None,
                },
            )]),
            &config.pools,
        )
        .expect("static auth should initialize");
        let identity = auth
            .authenticate("secret")
            .await
            .expect("authentication should not fail")
            .expect("token should match");
        assert_eq!(identity.subject.len(), 8);
        assert_eq!(identity.bucket_key.len(), 64);
        assert!(identity.read_only);
        assert_eq!(identity.key_prefix.as_deref(), Some("tenant:"));
        assert!(!format!("{identity:?}").contains(&identity.bucket_key));
    }

    #[tokio::test]
    async fn abstains_for_an_unknown_token() {
        let auth = StaticAuth::new(HashMap::new(), &HashMap::new())
            .expect("empty static auth should initialize");
        assert_eq!(auth.authenticate("wrong").await, Ok(None));
    }

    #[tokio::test]
    async fn satisfies_the_authenticator_contract() {
        let digest: [u8; 32] = Sha256::digest(b"secret").into();
        let config = crate::config::Config::from_json(
            r#"{"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
        )
        .expect("pool config should parse");
        let auth: Arc<dyn Authenticator> = Arc::new(
            StaticAuth::new(
                HashMap::from([(
                    digest,
                    StaticTokenConfig {
                        pool: "cache".to_owned(),
                        read_only: false,
                        legacy: false,
                        allowed_commands: None,
                        blocked_commands: HashSet::new(),
                        allowed_script_sha256: HashSet::new(),
                        key_prefix: None,
                    },
                )]),
                &config.pools,
            )
            .expect("static auth should initialize"),
        );
        crate::testsupport::authenticator_contract(auth, "secret", "not-configured").await;
    }
}
