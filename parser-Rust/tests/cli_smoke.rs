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
    assert!(json.get("moduleName").is_some());
    assert!(json.get("cargoTomlPath").is_some());
    assert!(json.get("numOfCargoToml").is_some());
}

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(relative)
}
