use std::fs;
use std::path::PathBuf;

#[test]
fn composition_root_supplies_peer_addresses_and_starts_the_metrics_listener() {
    let source = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("composition root must be readable");
    assert!(source.contains("app.clone().layer(Extension(ConnectInfo(peer)))"));
    assert!(source.contains(".with_http_listener(metrics_address)"));
    assert!(source.contains("http::observability::register_metrics(&config)"));
}
