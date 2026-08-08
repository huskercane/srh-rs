use std::sync::Arc;

use crate::ports::Authenticator;

/// Shared minimum contract for credential-format-specific authenticators.
pub async fn authenticator_contract(
    authenticator: Arc<dyn Authenticator>,
    valid_credential: &str,
    unrecognized_credential: &str,
) {
    assert!(
        authenticator
            .authenticate(valid_credential)
            .await
            .expect("a valid credential must not fail")
            .is_some(),
        "a valid credential must produce an identity"
    );
    assert_eq!(
        authenticator.authenticate(unrecognized_credential).await,
        Ok(None),
        "an unrecognized credential must abstain so the chain can continue"
    );
}
