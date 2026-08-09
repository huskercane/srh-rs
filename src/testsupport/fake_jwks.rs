use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::domain::identity::{CachedKey, JwksError};
use crate::ports::JwksSource;

/// In-memory JWKS port fake with an observable lookup count.
#[derive(Clone, Default)]
pub struct FakeJwks {
    keys: Arc<Mutex<HashMap<String, CachedKey>>>,
    calls: Arc<AtomicUsize>,
}

impl FakeJwks {
    pub fn new(keys: HashMap<String, CachedKey>) -> Self {
        Self {
            keys: Arc::new(Mutex::new(keys)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl JwksSource for FakeJwks {
    async fn key_for(&self, kid: &str) -> Result<CachedKey, JwksError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(kid)
            .cloned()
            .ok_or(JwksError::NotFound)
    }
}
