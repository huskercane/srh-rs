use std::fs;
use std::path::PathBuf;

fn source(path: &str) -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("repository source must be readable")
}

#[test]
fn composition_root_supplies_peer_addresses_and_starts_the_metrics_listener() {
    let source = source("src/main.rs");
    assert!(source.contains("app.clone().layer(Extension(ConnectInfo(peer)))"));
    assert!(source.contains(".with_http_listener(metrics_address)"));
    assert!(source.contains("http::observability::register_metrics(&config)"));
}

#[test]
fn release_build_matches_the_linux_production_artifact_contract() {
    let workflow = source(".github/workflows/release.yml");
    for required in [
        "BIN_NAME: srh-rs",
        "TARGET: x86_64-unknown-linux-musl",
        "cargo build --release --locked --target \"$TARGET\"",
        "deploy/srh-rs.service",
        "srh-config/tokens.example.json",
        "ghcr.io/${{ github.repository }}:$GITHUB_REF_NAME",
        "softprops/action-gh-release@v2",
    ] {
        assert!(
            workflow.contains(required),
            "release workflow omitted {required}"
        );
    }

    let unit = source("deploy/srh-rs.service");
    assert!(unit.contains("LoadCredential=srh-config:/etc/srh-rs/tokens.json"));
    assert!(unit.contains("Environment=SRH_CONFIG_PATH=%d/srh-config"));
    assert!(unit.contains("After=network-online.target"));
    assert!(unit.contains("Wants=network-online.target"));
    let directives = unit
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!directives.contains("Requires="));
    assert!(!directives.contains("BindsTo="));
}
