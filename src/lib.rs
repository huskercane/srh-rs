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
use ports::{Authenticator, Clock, ExecutorProvider};

/// Shared application dependencies used by every inbound HTTP handler.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<dyn ExecutorProvider>,
    pub authenticator: Arc<dyn Authenticator>,
    pub clock: Arc<dyn Clock>,
    pub cfg: Arc<Config>,
}
