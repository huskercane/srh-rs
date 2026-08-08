use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_IMPORTS: [&str; 5] = [
    "use fred",
    "use axum",
    "use reqwest",
    "use hyper",
    "use tower",
];

#[test]
fn domain_and_ports_do_not_import_adapter_dependencies() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for directory in ["src/domain", "src/ports"] {
        inspect(&root.join(directory));
    }
}

fn inspect(path: &Path) {
    for entry in fs::read_dir(path).expect("architecture directory must be readable") {
        let path = entry.expect("architecture entry must be readable").path();
        if path.is_dir() {
            inspect(&path);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).expect("Rust source must be readable");
            for forbidden in FORBIDDEN_IMPORTS {
                assert!(
                    !source.contains(forbidden),
                    "{} imports forbidden dependency via `{forbidden}`",
                    path.display()
                );
            }
        }
    }
}
