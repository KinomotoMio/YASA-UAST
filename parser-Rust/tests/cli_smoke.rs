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

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(relative)
}
