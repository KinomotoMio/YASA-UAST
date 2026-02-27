use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_uast4rust"))
        .args(args)
        .output()
        .expect("failed to run uast4rust")
}

#[test]
fn single_mode_writes_minimal_uast_with_rust_language() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_file = fixture_path("single/basic.rs");
    let output_file = temp.path().join("out").join("single.json");

    let out = run_cli(&[
        "-rootDir",
        source_file.to_str().expect("fixture path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
        "-single",
    ]);

    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_bytes = fs::read(&output_file).expect("read output");
    let json: Value = serde_json::from_slice(&json_bytes).expect("valid json");

    assert!(json.get("packageInfo").is_some());
    assert_eq!(
        json.get("moduleName").and_then(Value::as_str),
        Some("__single_module__")
    );
    assert!(json.get("cargoTomlPath").is_some());
    assert!(json.get("numOfCargoToml").is_some());

    let files = json
        .get("packageInfo")
        .and_then(|v| v.get("files"))
        .and_then(Value::as_object)
        .expect("packageInfo.files object");
    assert_eq!(files.len(), 1);
    let only_file = files.values().next().expect("file entry");
    assert_eq!(
        only_file
            .get("node")
            .and_then(|v| v.get("language"))
            .and_then(Value::as_str),
        Some("rust")
    );
}

#[test]
fn project_mode_writes_required_top_level_fields() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project_dir = fixture_path("project/basic");
    let output_file = temp.path().join("out").join("project.json");

    let out = run_cli(&[
        "-rootDir",
        project_dir.to_str().expect("utf8 path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
    ]);

    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_bytes = fs::read(&output_file).expect("read output");
    let json: Value = serde_json::from_slice(&json_bytes).expect("valid json");

    assert!(json.get("packageInfo").is_some());
    assert_eq!(json.get("moduleName").and_then(Value::as_str), Some("demo"));
    assert_eq!(
        json.get("cargoTomlPath").and_then(Value::as_str),
        Some("/Cargo.toml")
    );
    assert_eq!(json.get("numOfCargoToml").and_then(Value::as_u64), Some(1));
}

#[test]
fn single_mode_lowers_core_syntax_and_matches_golden() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_file = fixture_path("single/core_syntax.rs");
    let output_file = temp.path().join("out").join("core.json");

    let out = run_cli(&[
        "-rootDir",
        source_file.to_str().expect("fixture path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
        "-single",
    ]);

    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output_bytes = fs::read(&output_file).expect("read output");
    let mut actual: Value = serde_json::from_slice(&output_bytes).expect("valid output json");
    normalize_single_file_paths(&mut actual);

    let expected_raw = fs::read_to_string(fixture_path("single/expected.core.json"))
        .expect("read expected core golden");
    let expected: Value = serde_json::from_str(&expected_raw).expect("valid expected json");

    assert_eq!(
        actual, expected,
        "single file core syntax output mismatches golden"
    );
}

#[test]
fn single_mode_rejects_output_equal_to_source_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_file = temp.path().join("same.rs");
    fs::write(&source_file, "fn main() {}\n").expect("write source file");

    let out = run_cli(&[
        "-rootDir",
        source_file.to_str().expect("utf8 path"),
        "-output",
        source_file.to_str().expect("utf8 path"),
        "-single",
    ]);

    assert!(
        !out.status.success(),
        "cli unexpectedly succeeded with same input/output path"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to overwrite source file"),
        "unexpected error message: {stderr}"
    );

    let source_after = fs::read_to_string(&source_file).expect("read source file");
    assert_eq!(source_after, "fn main() {}\n");
}

#[test]
fn project_mode_matches_golden_and_is_stable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project_dir = fixture_path("project/multi");
    let output_file_1 = temp.path().join("out").join("project1.json");
    let output_file_2 = temp.path().join("out").join("project2.json");

    let out1 = run_cli(&[
        "-rootDir",
        project_dir.to_str().expect("utf8 path"),
        "-output",
        output_file_1.to_str().expect("utf8 path"),
    ]);
    assert!(
        out1.status.success(),
        "first cli run failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    let out2 = run_cli(&[
        "-rootDir",
        project_dir.to_str().expect("utf8 path"),
        "-output",
        output_file_2.to_str().expect("utf8 path"),
    ]);
    assert!(
        out2.status.success(),
        "second cli run failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    let bytes_1 = fs::read(&output_file_1).expect("read first output");
    let bytes_2 = fs::read(&output_file_2).expect("read second output");
    assert_eq!(bytes_1, bytes_2, "project output is not stable across runs");

    let actual: Value = serde_json::from_slice(&bytes_1).expect("valid project output json");
    let expected_raw = fs::read_to_string(fixture_path("project/multi/expected.project.json"))
        .expect("read golden json");
    let expected: Value = serde_json::from_str(&expected_raw).expect("valid golden json");
    assert_eq!(
        actual, expected,
        "project discovery output mismatches golden"
    );
}

#[test]
fn project_mode_skips_hidden_directories_when_discovering_manifests() {
    let temp = tempfile::tempdir().expect("tempdir");
    let project_dir = temp.path().join("proj");
    fs::create_dir_all(&project_dir).expect("create project dir");
    fs::write(
        project_dir.join("Cargo.toml"),
        "[package]\nname = \"rootpkg\"\nversion = \"0.1.0\"\n",
    )
    .expect("write root manifest");

    let hidden_manifest = project_dir.join(".cargo/registry/src/foo");
    fs::create_dir_all(&hidden_manifest).expect("create hidden directory");
    fs::write(
        hidden_manifest.join("Cargo.toml"),
        "[package]\nname = \"vendored\"\nversion = \"0.1.0\"\n",
    )
    .expect("write hidden manifest");

    let output_file = temp.path().join("out").join("hidden-skip.json");
    let out = run_cli(&[
        "-rootDir",
        project_dir.to_str().expect("utf8 path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
    ]);

    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_bytes = fs::read(&output_file).expect("read output");
    let json: Value = serde_json::from_slice(&json_bytes).expect("valid json");

    assert_eq!(
        json.get("moduleName").and_then(Value::as_str),
        Some("rootpkg")
    );
    assert_eq!(
        json.get("cargoTomlPath").and_then(Value::as_str),
        Some("/Cargo.toml")
    );
    assert_eq!(json.get("numOfCargoToml").and_then(Value::as_u64), Some(1));
}

#[test]
fn single_mode_preserves_wildcard_let_initializer_call() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_file = temp.path().join("wildcard.rs");
    fs::write(
        &source_file,
        "fn sink(x: i32) {}\nfn f(input: i32) { let _ = sink(input); }\n",
    )
    .expect("write source");
    let output_file = temp.path().join("out").join("wildcard.json");

    let out = run_cli(&[
        "-rootDir",
        source_file.to_str().expect("utf8 path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
        "-single",
    ]);
    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_bytes = fs::read(&output_file).expect("read output");
    let json: Value = serde_json::from_slice(&json_bytes).expect("valid json");
    assert!(
        count_nodes_of_type(&json, "CallExpression") >= 1,
        "expected at least one CallExpression in lowered output"
    );
}

#[test]
fn single_mode_lowers_compound_assignment_operator() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_file = temp.path().join("assign_op.rs");
    fs::write(&source_file, "fn f() { let mut v = 0; v += 1; }\n").expect("write source");
    let output_file = temp.path().join("out").join("assign_op.json");

    let out = run_cli(&[
        "-rootDir",
        source_file.to_str().expect("utf8 path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
        "-single",
    ]);
    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_bytes = fs::read(&output_file).expect("read output");
    let json: Value = serde_json::from_slice(&json_bytes).expect("valid json");
    assert!(
        has_assignment_operator(&json, "+="),
        "expected AssignmentExpression with operator '+='"
    );
}

#[test]
fn single_mode_lowers_unary_negation_in_initializer() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_file = temp.path().join("unary.rs");
    fs::write(&source_file, "fn f() { let x = -1; }\n").expect("write source");
    let output_file = temp.path().join("out").join("unary.json");

    let out = run_cli(&[
        "-rootDir",
        source_file.to_str().expect("utf8 path"),
        "-output",
        output_file.to_str().expect("utf8 path"),
        "-single",
    ]);
    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json_bytes = fs::read(&output_file).expect("read output");
    let json: Value = serde_json::from_slice(&json_bytes).expect("valid json");
    assert!(
        count_nodes_of_type(&json, "UnaryExpression") >= 1,
        "expected UnaryExpression for negative initializer"
    );
    let serialized = serde_json::to_string(&json).expect("serialize output");
    assert!(
        !serialized.contains("__rhs__")
            && !serialized.contains("__lhs__")
            && !serialized.contains("__callee__")
            && !serialized.contains("__receiver__")
            && !serialized.contains("__object__")
            && !serialized.contains("__param__"),
        "placeholder identifiers should not appear in output"
    );
}

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(relative)
}

fn normalize_single_file_paths(json: &mut Value) {
    let files = json
        .get_mut("packageInfo")
        .and_then(|v| v.get_mut("files"))
        .and_then(Value::as_object_mut)
        .expect("packageInfo.files object");
    assert_eq!(files.len(), 1, "single-mode output should contain one file");

    let original_key = files.keys().next().cloned().expect("single file key");
    let mut file_entry = files
        .remove(&original_key)
        .expect("single file entry should exist");

    if let Some(uri) = file_entry
        .get_mut("node")
        .and_then(|node| node.get_mut("uri"))
    {
        *uri = Value::String("__FILE__".to_string());
    }

    files.insert("__FILE__".to_string(), file_entry);
}

fn count_nodes_of_type(value: &Value, target_type: &str) -> usize {
    match value {
        Value::Object(map) => {
            let self_count = map
                .get("type")
                .and_then(Value::as_str)
                .map(|node_type| usize::from(node_type == target_type))
                .unwrap_or(0);
            self_count
                + map
                    .values()
                    .map(|child| count_nodes_of_type(child, target_type))
                    .sum::<usize>()
        }
        Value::Array(items) => items
            .iter()
            .map(|child| count_nodes_of_type(child, target_type))
            .sum(),
        _ => 0,
    }
}

fn has_assignment_operator(value: &Value, operator: &str) -> bool {
    match value {
        Value::Object(map) => {
            let self_match = map
                .get("type")
                .and_then(Value::as_str)
                .zip(map.get("operator").and_then(Value::as_str))
                .map(|(node_type, node_operator)| {
                    node_type == "AssignmentExpression" && node_operator == operator
                })
                .unwrap_or(false);
            self_match
                || map
                    .values()
                    .any(|child| has_assignment_operator(child, operator))
        }
        Value::Array(items) => items
            .iter()
            .any(|child| has_assignment_operator(child, operator)),
        _ => false,
    }
}
