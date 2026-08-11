use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use axum::extract::Request;
use axum::response::Response;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

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
    /// The whole identity, not copies of two of its fields. The handler already holds an
    /// `Arc<Identity>`, so recording it costs one refcount bump instead of allocating a
    /// fresh subject and pool string on every request.
    identity: Option<Arc<Identity>>,
    command: Option<CommandLabel>,
    pipeline_len: usize,
}

impl AuditContext {
    pub fn identity(&self, identity: &Arc<Identity>) {
        self.lock().identity = Some(Arc::clone(identity));
    }

    pub fn command(&self, command: Option<&str>, pipeline_len: usize) {
        let mut fields = self.lock();
        fields.command = command.map(CommandLabel::uppercase);
        fields.pipeline_len = pipeline_len;
    }

    fn lock(&self) -> MutexGuard<'_, AuditFields> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The longest command label the audit line retains.
///
/// Redis's longest command name is well under this. A longer name is not a command Redis
/// has, so the ACL will have refused it and the truncated label still identifies what was
/// attempted.
const COMMAND_LABEL_CAPACITY: usize = 32;

/// An uppercased command name stored inline.
///
/// The audit line is written after the handler returns, so the label cannot borrow the
/// request body, and `str::to_ascii_uppercase` would allocate on every request.
struct CommandLabel {
    bytes: [u8; COMMAND_LABEL_CAPACITY],
    len: usize,
}

impl CommandLabel {
    fn uppercase(command: &str) -> Self {
        let mut label = Self {
            bytes: [0; COMMAND_LABEL_CAPACITY],
            len: 0,
        };
        for byte in command.bytes().take(COMMAND_LABEL_CAPACITY) {
            label.bytes[label.len] = byte.to_ascii_uppercase();
            label.len += 1;
        }
        label
    }

    fn as_str(&self) -> &str {
        // Truncation is by byte, so a multi-byte character can be cut in half. The label is
        // diagnostic only, so fall back rather than fail the request that produced it.
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or("-")
    }
}

/// Emits the canonical request-completion event and the request metrics.
///
/// This is a hand-written `Layer` rather than `axum::middleware::from_fn`: `from_fn` erases
/// its future into a `Pin<Box<dyn Future>>`, which is a heap allocation on every request
/// through the stack. The concrete future here costs none.
#[derive(Clone, Copy, Default)]
pub struct ObserveLayer;

impl<S> Layer<S> for ObserveLayer {
    type Service = Observe<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Observe { inner }
    }
}

#[derive(Clone)]
pub struct Observe<S> {
    inner: S,
}

impl<S> Service<Request> for Observe<S>
where
    S: Service<Request, Response = Response>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ObserveFuture<S::Future>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let endpoint = endpoint_label(request.uri().path());
        let audit = AuditContext::default();
        request.extensions_mut().insert(audit.clone());
        ObserveFuture {
            inner: self.inner.call(request),
            started: Instant::now(),
            endpoint,
            audit,
            _in_flight: InFlight::enter(),
        }
    }
}

pin_project! {
    pub struct ObserveFuture<F> {
        #[pin]
        inner: F,
        started: Instant,
        endpoint: &'static str,
        audit: AuditContext,
        _in_flight: InFlight,
    }
}

impl<F, E> Future for ObserveFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let response = ready!(this.inner.poll(context));
        // The inner stack is `Infallible`, so the error arm carries no response to record.
        if let Ok(response) = &response {
            record(*this.started, this.endpoint, this.audit, response);
        }
        Poll::Ready(response)
    }
}

/// Holds the in-flight gauge for the lifetime of one request.
///
/// Decrementing on drop rather than on completion also covers the request whose future is
/// dropped before it finishes — a client that disconnects mid-request used to leave the
/// gauge permanently incremented.
struct InFlight;

impl InFlight {
    fn enter() -> Self {
        metrics::gauge!("srh_http_in_flight").increment(1.0);
        Self
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        metrics::gauge!("srh_http_in_flight").decrement(1.0);
    }
}

fn record(started: Instant, endpoint: &'static str, audit: &AuditContext, response: &Response) {
    let status = response.status().as_u16();
    let label = status_label(status);
    let elapsed = started.elapsed();
    metrics::counter!("srh_http_requests_total", "endpoint" => endpoint, "status" => label)
        .increment(1);
    metrics::histogram!("srh_http_request_duration_seconds", "endpoint" => endpoint, "status" => label)
        .record(elapsed.as_secs_f64());

    // The audit event records who ran what. A succeeding health probe has neither: staging
    // was emitting 8,640 of these a day, one every ten seconds, and they were 100% of this
    // service's log volume — every line reading subject="-" command="-" status=200. The
    // metrics above already carry the probe result, so only a failing probe earns a line.
    if is_probe(endpoint) && (200..300).contains(&status) {
        return;
    }

    let fields = audit.lock();
    tracing::info!(
        subject = fields
            .identity
            .as_ref()
            .map_or("-", |identity| identity.subject.as_str()),
        pool = fields
            .identity
            .as_ref()
            .map_or("-", |identity| identity.pool.as_str()),
        command = fields.command.as_ref().map_or("-", CommandLabel::as_str),
        status,
        latency_ms = elapsed.as_millis(),
        pipeline_len = fields.pipeline_len,
        endpoint,
        "request completed"
    );
}

/// Bounded metric label for a response status.
///
/// Metric label cardinality must not follow anything a client can steer, and a
/// `&'static str` also keeps the per-request path allocation-free: the status was
/// previously formatted into a `String` and then cloned once per metric.
fn status_label(status: u16) -> &'static str {
    match status {
        200 => "200",
        400 => "400",
        401 => "401",
        403 => "403",
        404 => "404",
        405 => "405",
        408 => "408",
        413 => "413",
        429 => "429",
        500 => "500",
        502 => "502",
        503 => "503",
        _ => "other",
    }
}

/// Whether an endpoint is a liveness/readiness probe rather than a client request.
fn is_probe(endpoint: &str) -> bool {
    matches!(endpoint, "/health" | "/ready")
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
    use std::convert::Infallible;
    use std::future::Pending;

    use axum::body::Body;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

    use super::{
        AuditContext, CommandLabel, Context, Layer, ObserveLayer, Poll, Request, Response, Service,
        endpoint_label, status_label,
    };

    /// An inner service whose response never arrives, so the request can be abandoned.
    struct NeverResponds;

    impl Service<Request> for NeverResponds {
        type Response = Response;
        type Error = Infallible;
        type Future = Pending<Result<Response, Infallible>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Request) -> Self::Future {
            std::future::pending()
        }
    }

    fn in_flight(handle: &PrometheusHandle) -> f64 {
        handle
            .render()
            .lines()
            .find_map(|line| line.strip_prefix("srh_http_in_flight "))
            .and_then(|value| value.parse().ok())
            .unwrap_or(f64::NAN)
    }

    #[test]
    fn a_request_abandoned_before_completion_releases_the_in_flight_gauge() {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("the test process installs exactly one recorder");
        let mut service = ObserveLayer.layer(NeverResponds);

        let pending = service.call(Request::new(Body::empty()));
        assert_eq!(in_flight(&handle), 1.0);

        // A client that disconnects mid-request drops the response future without ever
        // completing it. Releasing the gauge on drop is what keeps it from ratcheting up
        // for the life of the process.
        drop(pending);
        assert_eq!(in_flight(&handle), 0.0);
    }

    #[test]
    fn endpoint_metric_labels_have_bounded_cardinality() {
        assert_eq!(endpoint_label("/pipeline"), "/pipeline");
        assert_eq!(endpoint_label("/attacker-controlled/one"), "other");
        assert_eq!(endpoint_label("/attacker-controlled/two"), "other");
    }

    /// Counts emitted `tracing` events without pulling in a formatting subscriber.
    struct CountEvents(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl tracing::Subscriber for CountEvents {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::Id, _: &tracing::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn enter(&self, _: &tracing::Id) {}
        fn exit(&self, _: &tracing::Id) {}
    }

    #[test]
    fn a_healthy_probe_is_not_audited_but_a_failing_one_is() {
        use std::sync::atomic::Ordering;

        let events = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tracing::subscriber::with_default(CountEvents(std::sync::Arc::clone(&events)), || {
            let audit = AuditContext::default();

            super::record(
                std::time::Instant::now(),
                "/health",
                &audit,
                &Response::new(Body::empty()),
            );
            assert_eq!(
                events.load(Ordering::Relaxed),
                0,
                "a succeeding probe has no subject and no command; it must not be audited"
            );

            let mut failed = Response::new(Body::empty());
            *failed.status_mut() = axum::http::StatusCode::SERVICE_UNAVAILABLE;
            super::record(std::time::Instant::now(), "/ready", &audit, &failed);
            assert_eq!(
                events.load(Ordering::Relaxed),
                1,
                "a failing probe is the case worth keeping"
            );

            super::record(
                std::time::Instant::now(),
                "/",
                &audit,
                &Response::new(Body::empty()),
            );
            assert_eq!(
                events.load(Ordering::Relaxed),
                2,
                "client requests are audited regardless of status"
            );
        });
    }

    #[test]
    fn status_metric_labels_have_bounded_cardinality() {
        assert_eq!(status_label(200), "200");
        assert_eq!(status_label(503), "503");
        assert_eq!(status_label(418), "other");
        assert_eq!(status_label(599), "other");
    }

    #[test]
    fn command_labels_uppercase_and_truncate_without_allocating_a_string() {
        assert_eq!(CommandLabel::uppercase("get").as_str(), "GET");
        let long = "a".repeat(super::COMMAND_LABEL_CAPACITY * 2);
        assert_eq!(
            CommandLabel::uppercase(&long).as_str(),
            "A".repeat(super::COMMAND_LABEL_CAPACITY),
            "an over-long name must truncate rather than allocate or panic"
        );
    }

    #[test]
    fn a_label_truncated_mid_character_falls_back_instead_of_panicking() {
        // '€' is three bytes and the capacity is not a multiple of three, so the cut lands
        // inside a character.
        let name = "€".repeat(super::COMMAND_LABEL_CAPACITY);
        assert_eq!(CommandLabel::uppercase(&name).as_str(), "-");
    }
}
