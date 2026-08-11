use std::fs;
use std::path::PathBuf;

fn source(path: &str) -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

#[test]
fn runtime_and_scheduled_gates_keep_protections_wired() {
    let main = source("src/main.rs");
    assert!(main.contains("stream.set_nodelay(true)"));

    let router = source("src/http/mod.rs");
    // This gate exists to keep deliberate overload from becoming log amplification.
    // `TraceLayer` used to carry it via `on_failure(())`, which disabled the callback that
    // logs every shed 503 at ERROR. The layer has since been removed outright — at the
    // production filter it emitted nothing at all, because `DefaultMakeSpan` and
    // `DEFAULT_MESSAGE_LEVEL` are both DEBUG, while costing 11% of per-request CPU — so
    // the hazard went with it. The protection now is that `ObserveLayer` is the only
    // request logger, and it records a shed response at INFO like any other status.
    assert!(router.contains(".layer(observability::ObserveLayer)"));
    // Matches the constructor, not the bare name: the router carries a comment explaining
    // why the layer is absent, and a gate that fires on its own rationale is a gate nobody
    // can document.
    assert!(
        !router.contains("TraceLayer::new_for_http"),
        "re-adding TraceLayer restores the shed-log amplification this gate exists to prevent"
    );

    let workflow = source(".github/workflows/load.yml");
    assert!(workflow.contains("schedule:"));
    assert!(workflow.contains("./scripts/phase9-load.sh"));

    let mutation_workflow = source(".github/workflows/mutation.yml");
    assert!(mutation_workflow.contains("schedule:"));
    assert!(
        mutation_workflow.contains("cargo test --test mutation_guard -- --ignored --nocapture")
    );

    for document in [source("README.md"), source("srh-rust-spec.md")] {
        for grant in ["+ping", "+info", "+command|info"] {
            assert!(document.contains(grant), "documentation omitted {grant}");
        }
        assert!(document.contains("Do not") && document.contains("`+hello`"));
        assert!(!document.contains("+ping +hello"));
        assert!(!document.contains("`+hello` and `+ping`"));
        assert!(document.contains("+multi +exec +discard"));
    }
    let ci = source(".github/workflows/ci.yml");
    for grant in ["+ping", "+info", "+command\\|info"] {
        assert!(ci.contains(grant), "CI Redis ACL omitted {grant}");
    }
    assert!(!ci.contains("+hello"), "CI Redis ACL must not grant HELLO");
    assert!(ci.contains("+multi +exec +discard"));
    assert!(ci.contains("parity policy-scope skip:"));
    assert!(ci.contains("parity documented protocol skip:"));
    assert!(ci.contains("parity backend-scope skip:"));
    assert!(ci.contains("fc3089b69f583bc2a34bb1c4f9b8871891408cdc"));
    assert!(ci.contains("bun-version: 1.3.6"));
    assert!(ci.contains("bun test pkg --bail --timeout 20000"));
    assert!(ci.contains("upstash-parity-policy.patch"));
    assert!(ci.contains("upstash-parity-protocol.patch"));
    assert!(ci.contains("upstash-parity-backend.patch"));
    assert!(!ci.contains("denoland/deno"));

    let shell = source("scripts/phase9-load.sh");
    for profile in ["overload", "backend-death", "slow-client"] {
        assert!(shell.contains(profile));
    }

    let runner = source("scripts/phase9-load.py");
    for required_assertion in [
        "accepted_p99 < baseline_p99 * 5",
        "rejected_p99 < 10",
        "peak_rss < baseline_rss * 1.20",
        "fast_p99 < 10",
        "after_rate >= before_rate * 0.8",
        "max(gauge_values) == 0",
        "sample.status == 408",
        "percentile(accepted, 0.99) < baseline * 2",
    ] {
        assert!(runner.contains(required_assertion));
    }
}
