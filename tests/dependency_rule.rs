use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_CRATES: [&str; 6] = ["fred", "axum", "reqwest", "hyper", "tower", "futures_util"];

/// Intra-crate layering: `domain/` and `ports/` declare the configuration types they need and
/// `config.rs` populates them, so a policy or port never reaches into the configuration layer
/// for one. `crate::config` covers the direct path and `super::config` covers any relative
/// walk up to it, including `super::super::config`.
const FORBIDDEN_MODULE_PATHS: [&str; 2] = ["crate::config", "super::config"];

#[test]
fn domain_and_ports_do_not_reference_adapter_dependencies() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for directory in ["src/domain", "src/ports"] {
        let directory = root.join(directory);
        assert!(directory.is_dir(), "{} must exist", directory.display());
        assert!(
            inspect(&directory) > 0,
            "{} must contain Rust source files",
            directory.display()
        );
    }
}

fn inspect(path: &Path) -> usize {
    let mut rust_files = 0;
    for entry in fs::read_dir(path).expect("architecture directory must be readable") {
        let path = entry.expect("architecture entry must be readable").path();
        if path.is_dir() {
            rust_files += inspect(&path);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            rust_files += 1;
            inspect_source(&path);
        }
    }
    rust_files
}

fn inspect_source(path: &Path) {
    let source = fs::read_to_string(path).expect("Rust source must be readable");
    let code = strip_comments_and_literals(&source);
    if let Some(identifier) = forbidden_identifier(&code) {
        panic!(
            "{} references forbidden crate `{identifier}`",
            path.display()
        );
    }
    if let Some(module_path) = forbidden_module_path(&code) {
        panic!(
            "{} references forbidden module path `{module_path}`; \
             domain and ports own their configuration types and are populated from config.rs, \
             never the other way round",
            path.display()
        );
    }
}

fn forbidden_identifier(code: &str) -> Option<&str> {
    code.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .find(|token| FORBIDDEN_CRATES.contains(token))
}

fn forbidden_module_path(code: &str) -> Option<&'static str> {
    let compact: String = code
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    FORBIDDEN_MODULE_PATHS
        .into_iter()
        .find(|forbidden| contains_path(&compact, forbidden))
}

/// Matches `forbidden` only as a complete path segment, so a module whose name merely starts
/// with `config` (`crate::configuration`) is not mistaken for the configuration layer.
fn contains_path(compact: &str, forbidden: &str) -> bool {
    compact.match_indices(forbidden).any(|(index, _)| {
        compact[index + forbidden.len()..]
            .chars()
            .next()
            .is_none_or(|next| !next.is_ascii_alphanumeric() && next != '_')
    })
}

fn strip_comments_and_literals(source: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment(usize),
        String,
        RawString(usize),
        Character,
    }

    let chars: Vec<char> = source.chars().collect();
    let mut output = String::with_capacity(source.len());
    let mut state = State::Code;
    let mut index = 0;

    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            State::Code if let Some((length, hashes)) = raw_string_start(&chars, index) => {
                state = State::RawString(hashes);
                output.extend(std::iter::repeat_n(' ', length));
                index += length;
            }
            State::Code if current == '/' && next == Some('/') => {
                state = State::LineComment;
                output.push_str("  ");
                index += 2;
            }
            State::Code if current == '/' && next == Some('*') => {
                state = State::BlockComment(1);
                output.push_str("  ");
                index += 2;
            }
            State::Code if current == '"' => {
                state = State::String;
                output.push(' ');
                index += 1;
            }
            State::Code if current == '\'' && starts_character_literal(&chars, index) => {
                state = State::Character;
                output.push(' ');
                index += 1;
            }
            State::Code => {
                output.push(current);
                index += 1;
            }
            State::LineComment if current == '\n' => {
                state = State::Code;
                output.push('\n');
                index += 1;
            }
            State::LineComment => {
                output.push(' ');
                index += 1;
            }
            State::BlockComment(depth) if current == '/' && next == Some('*') => {
                state = State::BlockComment(depth + 1);
                output.push_str("  ");
                index += 2;
            }
            State::BlockComment(depth) if current == '*' && next == Some('/') => {
                state = if depth == 1 {
                    State::Code
                } else {
                    State::BlockComment(depth - 1)
                };
                output.push_str("  ");
                index += 2;
            }
            State::BlockComment(depth) => {
                state = State::BlockComment(depth);
                output.push(if current == '\n' { '\n' } else { ' ' });
                index += 1;
            }
            State::String if current == '\\' => {
                output.push_str("  ");
                index += usize::from(next.is_some()) + 1;
            }
            State::String if current == '"' => {
                state = State::Code;
                output.push(' ');
                index += 1;
            }
            State::String => {
                output.push(if current == '\n' { '\n' } else { ' ' });
                index += 1;
            }
            State::RawString(hashes) if raw_string_end(&chars, index, hashes) => {
                output.extend(std::iter::repeat_n(' ', hashes + 1));
                index += hashes + 1;
                state = State::Code;
            }
            State::RawString(hashes) => {
                state = State::RawString(hashes);
                output.push(if current == '\n' { '\n' } else { ' ' });
                index += 1;
            }
            State::Character if current == '\\' => {
                output.push_str("  ");
                index += usize::from(next.is_some()) + 1;
            }
            State::Character if current == '\'' => {
                state = State::Code;
                output.push(' ');
                index += 1;
            }
            State::Character => {
                output.push(if current == '\n' { '\n' } else { ' ' });
                index += 1;
            }
        }
    }

    output
}

fn raw_string_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if chars.get(cursor) == Some(&'b') && chars.get(cursor + 1) == Some(&'r') {
        cursor += 2;
    } else if chars.get(cursor) == Some(&'r') {
        cursor += 1;
    } else {
        return None;
    }
    let hash_start = cursor;
    while chars.get(cursor) == Some(&'#') {
        cursor += 1;
    }
    (chars.get(cursor) == Some(&'"')).then_some((cursor - index + 1, cursor - hash_start))
}

fn raw_string_end(chars: &[char], index: usize, hashes: usize) -> bool {
    chars.get(index) == Some(&'"')
        && (0..hashes).all(|offset| chars.get(index + offset + 1) == Some(&'#'))
}

fn starts_character_literal(chars: &[char], index: usize) -> bool {
    let Some(first) = chars.get(index + 1) else {
        return false;
    };
    let closing = if *first != '\\' {
        index + 2
    } else if chars.get(index + 2) == Some(&'u') && chars.get(index + 3) == Some(&'{') {
        let mut cursor = index + 4;
        while chars.get(cursor).is_some_and(|character| *character != '}') {
            cursor += 1;
        }
        if chars.get(cursor) != Some(&'}') {
            return false;
        }
        cursor + 1
    } else {
        index + 3
    };
    chars.get(closing) == Some(&'\'')
}

#[cfg(test)]
mod tests {
    use super::{forbidden_identifier, forbidden_module_path, strip_comments_and_literals};

    #[test]
    fn scanner_ignores_comments_and_strings() {
        let source = r#"
            // fred::types::Value
            const NOTE: &str = "axum::Router";
            /* reqwest::Client */
            pub struct Safe;
        "#;
        let stripped = strip_comments_and_literals(source);
        assert!(!stripped.contains("fred"));
        assert!(!stripped.contains("axum"));
        assert!(!stripped.contains("reqwest"));
        assert!(stripped.contains("Safe"));
    }

    #[test]
    fn scanner_catches_fully_qualified_paths() {
        let code = strip_comments_and_literals("fn leak() -> Option<fred::types::Value> { None }");
        assert_eq!(forbidden_identifier(&code), Some("fred"));
    }

    #[test]
    fn scanner_handles_character_and_raw_string_literals() {
        let source = r####"
            const QUOTE: char = '"';
            const RAW: &str = r###"tower::Service"###;
            fn leak() -> Option<hyper::Error> { None }
        "####;
        let stripped = strip_comments_and_literals(source);
        assert!(!stripped.contains("tower"));
        assert_eq!(forbidden_identifier(&stripped), Some("hyper"));
    }

    #[test]
    fn scanner_catches_configuration_layer_imports() {
        for source in [
            "use crate::config::JwtConfig;",
            "use super::super::config::JwtConfig;",
            "fn build(cfg: &crate::config::JwtConfig) {}",
            "use crate :: config :: JwtConfig ;",
            "use crate::config::{JwtConfig, PoolConfig};",
        ] {
            let code = strip_comments_and_literals(source);
            assert!(
                forbidden_module_path(&code).is_some(),
                "configuration-layer import must be rejected: {source}"
            );
        }
    }

    #[test]
    fn scanner_allows_names_that_merely_begin_with_config() {
        for source in [
            "use crate::configuration::Thing;",
            "let configured = policy.config_floor();",
            "// crate::config::JwtConfig",
            "const NOTE: &str = \"crate::config\";",
        ] {
            let code = strip_comments_and_literals(source);
            assert_eq!(
                forbidden_module_path(&code),
                None,
                "must not be mistaken for the configuration layer: {source}"
            );
        }
    }
}
