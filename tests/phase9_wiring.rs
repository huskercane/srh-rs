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
    assert!(router.contains("TraceLayer::new_for_http().on_failure(())"));

    let workflow = source(".github/workflows/load.yml");
    assert!(workflow.contains("schedule:"));
    assert!(workflow.contains("./scripts/phase9-load.sh"));

    let mutation_workflow = source(".github/workflows/mutation.yml");
    assert!(mutation_workflow.contains("schedule:"));
    assert!(
        mutation_workflow.contains("cargo test --test mutation_guard -- --ignored --nocapture")
    );

    for document in [source("README.md"), source("srh-rust-spec.md")] {
        assert!(document.contains("+command|info +multi +exec +discard"));
    }
    let ci = source(".github/workflows/ci.yml");
    assert!(ci.contains("+ping +multi +exec +discard"));
    assert!(ci.contains("parity policy-scope skip:"));
    assert!(ci.contains("parity documented protocol skip:"));

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
