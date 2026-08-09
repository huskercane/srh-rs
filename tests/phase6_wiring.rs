use std::fs;
use std::path::PathBuf;

#[test]
fn composition_root_keeps_jwt_before_static_auth_and_sweeps_its_cache() {
    let source = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .expect("composition root must be readable");
    assert!(source.contains("AuthChain::new(vec![jwt_link, static_auth])"));
    assert!(source.contains("jwt.sweep_introspection_cache()"));
}
