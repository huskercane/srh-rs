use std::fs;
use std::path::PathBuf;

#[test]
fn command_handlers_transfer_pool_leases_into_consuming_execution_methods() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (file, call) in [
        ("src/http/command.rs", ".execute_and_release(command)"),
        (
            "src/http/pipeline.rs",
            "handle.pipeline_and_release(allowed_commands).await",
        ),
        (
            "src/http/multi_exec.rs",
            ".transaction_and_release(commands)",
        ),
    ] {
        let source = fs::read_to_string(root.join(file)).expect("handler source must be readable");
        assert!(
            source.contains(call),
            "{file} must consume its ExecutorHandle before response conversion"
        );
    }
}
