use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::identity::{AuthError, Identity};
use crate::ports::Authenticator;

pub struct AuthChain {
    links: Vec<Arc<dyn Authenticator>>,
}

impl AuthChain {
    pub fn new(links: Vec<Arc<dyn Authenticator>>) -> Self {
        Self { links }
    }
}

#[async_trait]
impl Authenticator for AuthChain {
    async fn authenticate(&self, bearer: &str) -> Result<Option<Identity>, AuthError> {
        for link in &self.links {
            if let Some(identity) = link.authenticate(bearer).await? {
                return Ok(Some(identity));
            }
        }
        Err(AuthError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    struct Abstain;

    #[async_trait]
    impl Authenticator for Abstain {
        async fn authenticate(&self, _bearer: &str) -> Result<Option<Identity>, AuthError> {
            Ok(None)
        }
    }

    struct Reject;

    #[async_trait]
    impl Authenticator for Reject {
        async fn authenticate(&self, _bearer: &str) -> Result<Option<Identity>, AuthError> {
            Err(AuthError::Rejected)
        }
    }

    #[tokio::test]
    async fn an_error_stops_the_chain() {
        let chain = AuthChain::new(vec![Arc::new(Abstain), Arc::new(Reject)]);
        assert_eq!(chain.authenticate("token").await, Err(AuthError::Rejected));
    }

    #[tokio::test]
    async fn exhaustion_is_unauthorized() {
        let chain = AuthChain::new(vec![Arc::new(Abstain)]);
        assert!(chain.authenticate("token").await.is_err());
    }
}
