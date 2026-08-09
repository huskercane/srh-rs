use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::domain::identity::Identity;

pub fn register_metrics(config: &crate::config::Config) {
    let _ = metrics::counter!("srh_http_requests_total", "endpoint" => "-", "status" => "-");
    let _ = metrics::histogram!("srh_http_request_duration_seconds", "endpoint" => "-", "status" => "-");
    metrics::gauge!("srh_http_in_flight").set(0.0);
    let _ = metrics::counter!("srh_rate_limit_rejections_total");
    for kind in [
        "missing_or_malformed",
        "rejected",
        "forbidden",
        "unavailable",
    ] {
        let _ = metrics::counter!("srh_auth_failures_total", "kind" => kind);
    }
    for cause in [
        "global_limit",
        "pool_queue_full",
        "acquire_timeout",
        "breaker_open",
        "response_too_large",
        "debt_forgiven_by_eviction",
    ] {
        let _ = metrics::counter!("srh_shed_total", "cause" => cause);
    }
    for pool in config.pools.keys() {
        let pool = pool.clone();
        let _ = metrics::counter!("srh_pool_builds_total", "pool" => pool.clone());
        let _ = metrics::counter!("srh_pool_evictions_total", "pool" => pool.clone());
        metrics::gauge!("srh_pool_active_connections", "pool" => pool.clone()).set(0.0);
        metrics::gauge!("srh_pool_permits_in_use", "pool" => pool.clone()).set(0.0);
        metrics::gauge!("srh_pool_waiter_depth", "pool" => pool.clone()).set(0.0);
        metrics::gauge!("srh_pool_breaker_state", "pool" => pool).set(0.0);
    }
}

#[derive(Clone, Default)]
pub struct AuditContext(Arc<Mutex<AuditFields>>);

#[derive(Default)]
struct AuditFields {
    subject: Option<String>,
    pool: Option<String>,
    command: Option<String>,
    pipeline_len: usize,
}

impl AuditContext {
    pub fn identity(&self, identity: &Identity) {
        let mut fields = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fields.subject = Some(identity.subject.clone());
        fields.pool = Some(identity.pool.clone());
    }

    pub fn command(&self, command: Option<&str>, pipeline_len: usize) {
        let mut fields = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fields.command = command.map(str::to_ascii_uppercase);
        fields.pipeline_len = pipeline_len;
    }
}

pub async fn observe_request(mut request: Request, next: Next) -> Response {
    let started = Instant::now();
    let endpoint = endpoint_label(request.uri().path());
    let audit = AuditContext::default();
    request.extensions_mut().insert(audit.clone());
    metrics::gauge!("srh_http_in_flight").increment(1.0);
    let response = next.run(request).await;
    metrics::gauge!("srh_http_in_flight").decrement(1.0);

    let status = response.status().as_u16().to_string();
    let elapsed = started.elapsed();
    metrics::counter!("srh_http_requests_total", "endpoint" => endpoint, "status" => status.clone())
        .increment(1);
    metrics::histogram!("srh_http_request_duration_seconds", "endpoint" => endpoint, "status" => status.clone())
        .record(elapsed.as_secs_f64());

    let fields = audit
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tracing::info!(
        subject = fields.subject.as_deref().unwrap_or("-"),
        pool = fields.pool.as_deref().unwrap_or("-"),
        command = fields.command.as_deref().unwrap_or("-"),
        status = %status,
        latency_ms = elapsed.as_millis(),
        pipeline_len = fields.pipeline_len,
        endpoint,
        "request completed"
    );
    response
}

fn endpoint_label(path: &str) -> &'static str {
    match path {
        "/" => "/",
        "/pipeline" => "/pipeline",
        "/multi-exec" => "/multi-exec",
        "/health" => "/health",
        "/ready" => "/ready",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::endpoint_label;

    #[test]
    fn endpoint_metric_labels_have_bounded_cardinality() {
        assert_eq!(endpoint_label("/pipeline"), "/pipeline");
        assert_eq!(endpoint_label("/attacker-controlled/one"), "other");
        assert_eq!(endpoint_label("/attacker-controlled/two"), "other");
    }
}
