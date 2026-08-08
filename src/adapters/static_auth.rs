use std::collections::HashMap;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::config::{StaticTokenConfig, digest_hex};
use crate::domain::identity::{AuthError, Identity};
use crate::ports::Authenticator;

pub struct StaticAuth {
    tokens: HashMap<[u8; 32], StaticTokenConfig>,
}

impl StaticAuth {
    pub fn new(tokens: HashMap<[u8; 32], StaticTokenConfig>) -> Self {
        Self { tokens }
    }
}

#[async_trait]
impl Authenticator for StaticAuth {
    async fn authenticate(&self, bearer: &str) -> Result<Option<Identity>, AuthError> {
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let Some(token) = self.tokens.get(&digest) else {
            return Ok(None);
        };
        let bucket_key = digest_hex(&digest);
        Ok(Some(Identity {
            subject: bucket_key[..8].to_owned(),
            bucket_key,
            pool: token.pool.clone(),
            read_only: token.read_only,
            is_admin: false,
            legacy: token.legacy,
            allowed_commands: token.allowed_commands.clone(),
            blocked_commands: token.blocked_commands.clone(),
            allowed_script_sha256: token.allowed_script_sha256.clone(),
            key_prefix: token.key_prefix.clone(),
        }))
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
        let auth = StaticAuth::new(HashMap::from([(
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
        )]));
        let identity = auth
            .authenticate("secret")
            .await
            .expect("authentication should not fail")
            .expect("token should match");
        assert_eq!(identity.subject.len(), 8);
        assert_eq!(identity.bucket_key.len(), 64);
        assert!(identity.read_only);
        assert!(!format!("{identity:?}").contains(&identity.bucket_key));
    }

    #[tokio::test]
    async fn abstains_for_an_unknown_token() {
        let auth = StaticAuth::new(HashMap::new());
        assert_eq!(auth.authenticate("wrong").await, Ok(None));
    }

    #[tokio::test]
    async fn satisfies_the_authenticator_contract() {
        let digest: [u8; 32] = Sha256::digest(b"secret").into();
        let auth: Arc<dyn Authenticator> = Arc::new(StaticAuth::new(HashMap::from([(
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
        )])));
        crate::testsupport::authenticator_contract(auth, "secret", "not-configured").await;
    }
}
