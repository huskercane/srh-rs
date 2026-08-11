#![forbid(unsafe_code)]

use std::sync::Arc;

pub mod adapters;
pub mod config;
pub mod domain;
pub mod error;
pub mod http;
pub mod ports;

#[cfg(any(test, feature = "testsupport"))]
pub mod testsupport;

use config::Config;
use domain::rate_limit::RateLimiter;
use ports::{Authenticator, Clock, ExecutorProvider};

/// Shared application dependencies used by every inbound HTTP handler.
pub struct AppStateInner {
    pub provider: Arc<dyn ExecutorProvider>,
    pub authenticator: Arc<dyn Authenticator>,
    pub clock: Arc<dyn Clock>,
    pub rate_limiter: Arc<RateLimiter>,
    pub cfg: Arc<Config>,
}

/// Cloneable handle to [`AppStateInner`].
///
/// axum clones the router state into every request, so the number of `Arc` fields
/// here is a per-request cost: a struct of five `Arc`s costs five atomic increments
/// on clone and five decrements on drop. Holding one `Arc` around the whole struct
/// makes that a single refcount pair regardless of how many dependencies are added.
pub struct AppState(Arc<AppStateInner>);

impl AppState {
    pub fn new(inner: AppStateInner) -> Self {
        Self(Arc::new(inner))
    }
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl std::ops::Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
