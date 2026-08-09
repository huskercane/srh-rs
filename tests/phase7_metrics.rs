use srh_rs::config::Config;

#[test]
fn phase_seven_metric_families_are_always_registered() {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .unwrap();
    let config =
        Config::from_json(r#"{"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#)
            .unwrap();
    srh_rs::http::observability::register_metrics(&config);
    let rendered = handle.render();
    for family in [
        "srh_http_requests_total",
        "srh_http_request_duration_seconds",
        "srh_http_in_flight",
        "srh_pool_active_connections",
        "srh_pool_builds_total",
        "srh_pool_evictions_total",
        "srh_auth_failures_total",
        "srh_rate_limit_rejections_total",
        "srh_pool_permits_in_use",
        "srh_pool_waiter_depth",
        "srh_shed_total",
        "srh_pool_breaker_state",
    ] {
        let declaration = format!("# TYPE {family} ");
        assert!(
            rendered.lines().any(|line| line.starts_with(&declaration)),
            "missing metric family {family}: {rendered}"
        );
    }
    for cause in [
        "global_limit",
        "pool_queue_full",
        "acquire_timeout",
        "breaker_open",
        "response_too_large",
        "debt_forgiven_by_eviction",
    ] {
        assert!(rendered.contains(&format!("cause=\"{cause}\"")));
    }
}
