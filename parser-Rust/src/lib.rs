mod model;

pub use model::{CompileUnit, NodeInfo, Output, PackagePathInfo, LANGUAGE};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const SINGLE_FILE_PACKAGE_NAME: &str = "__single__";
const SINGLE_FILE_MODULE_NAME: &str = "__single_module__";
const UNKNOWN_MODULE_NAME: &str = "__unknown_module__";
const CARGO_TOML_FILE_NAME: &str = "Cargo.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliArgs {
    pub root_dir: PathBuf,
    pub output: PathBuf,
    pub single: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgsError {
    HelpRequested,
    Message(String),
}

impl fmt::Display for ParseArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested => write!(f, "{}", usage()),
            Self::Message(msg) => write!(f, "{msg}"),
        }
    }
}

#[derive(Debug)]
pub enum RunError {
    InvalidInputPath {
        mode: &'static str,
        path: PathBuf,
    },
    OutputWouldOverwriteSource {
        source: PathBuf,
        output: PathBuf,
    },
    Io {
        context: String,
        source: std::io::Error,
    },
    Serialize {
        source: serde_json::Error,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInputPath { mode, path } => {
                write!(f, "{} mode expects a valid path: {}", mode, path.display())
            }
            Self::OutputWouldOverwriteSource { source, output } => write!(
                f,
                "refusing to overwrite source file in single mode: source={} output={}",
                source.display(),
                output.display()
            ),
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Serialize { source } => write!(f, "failed to serialize output json: {source}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInputPath { .. } => None,
            Self::OutputWouldOverwriteSource { .. } => None,
            Self::Io { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
        }
    }
}

pub fn usage() -> &'static str {
    "Usage: uast4rust -rootDir <path> -output <path> [-single]"
}

pub fn parse_args_from<I, S>(args: I) -> Result<CliArgs, ParseArgsError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut root_dir: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut single = false;
    let mut iter = args.into_iter().map(Into::into);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-rootDir" | "--rootDir" => {
                let value = next_arg_value(&mut iter, &arg)?;
                root_dir = Some(PathBuf::from(value));
            }
            "-output" | "--output" => {
                let value = next_arg_value(&mut iter, &arg)?;
                output = Some(PathBuf::from(value));
            }
            "-single" | "--single" => {
                single = true;
            }
            "-h" | "--help" => {
                return Err(ParseArgsError::HelpRequested);
            }
            unknown => {
                return Err(ParseArgsError::Message(format!(
                    "Unknown argument: {unknown}"
                )));
            }
        }
    }

    let root_dir = root_dir.ok_or_else(|| {
        ParseArgsError::Message(format!("Missing required argument: -rootDir\n{}", usage()))
    })?;
    let output = output.ok_or_else(|| {
        ParseArgsError::Message(format!("Missing required argument: -output\n{}", usage()))
    })?;

    Ok(CliArgs {
        root_dir,
        output,
        single,
    })
}

fn next_arg_value<I>(iter: &mut I, flag: &str) -> Result<String, ParseArgsError>
where
    I: Iterator<Item = String>,
{
    let value = iter
        .next()
        .ok_or_else(|| ParseArgsError::Message(format!("Missing value for '{}'", flag)))?;
    if is_known_flag(&value) {
        return Err(ParseArgsError::Message(format!(
            "Missing value for '{}'",
            flag
        )));
    }
    Ok(value)
}

fn is_known_flag(value: &str) -> bool {
    matches!(
        value,
        "-rootDir"
            | "--rootDir"
            | "-output"
            | "--output"
            | "-single"
            | "--single"
            | "-h"
            | "--help"
    )
}

pub fn parse_args() -> Result<CliArgs, ParseArgsError> {
    parse_args_from(env::args().skip(1))
}

pub fn run(cli: &CliArgs) -> Result<(), RunError> {
    if cli.single {
        parse_single_file(&cli.root_dir, &cli.output)
    } else {
        parse_project(&cli.root_dir, &cli.output)
    }
}

fn parse_single_file(file: &Path, output: &Path) -> Result<(), RunError> {
    if !file.is_file() {
        return Err(RunError::InvalidInputPath {
            mode: "single",
            path: file.to_path_buf(),
        });
    }

    fs::File::open(file).map_err(|source| RunError::Io {
        context: format!("failed to read file {}", file.display()),
        source,
    })?;

    let source_canonical = fs::canonicalize(file).map_err(|source| RunError::Io {
        context: format!("failed to canonicalize source file {}", file.display()),
        source,
    })?;
    let output_canonical = fs::canonicalize(output).unwrap_or_else(|_| output.to_path_buf());
    if source_canonical == output_canonical {
        return Err(RunError::OutputWouldOverwriteSource {
            source: source_canonical,
            output: output.to_path_buf(),
        });
    }

    let file_key = file.to_string_lossy().to_string();
    let mut files = BTreeMap::new();
    files.insert(
        file_key.clone(),
        NodeInfo {
            node: CompileUnit::empty(file_key),
            package_name: SINGLE_FILE_PACKAGE_NAME.to_string(),
        },
    );

    let output_model = Output {
        package_info: PackagePathInfo {
            path_name: "/".to_string(),
            files,
            subs: BTreeMap::new(),
        },
        module_name: SINGLE_FILE_MODULE_NAME.to_string(),
        cargo_toml_path: String::new(),
        num_of_cargo_toml: 0,
    };

    write_output(output, &output_model)
}

fn parse_project(root_dir: &Path, output: &Path) -> Result<(), RunError> {
    if !root_dir.is_dir() {
        return Err(RunError::InvalidInputPath {
            mode: "project",
            path: root_dir.to_path_buf(),
        });
    }

    let mut manifests = discover_cargo_toml(root_dir)?;
    manifests.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let module_name = manifests
        .iter()
        .find_map(|m| m.package_name.clone())
        .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string());
    let cargo_toml_path = manifests
        .first()
        .map(|m| m.rel_path.clone())
        .unwrap_or_default();
    let num_of_cargo_toml = manifests.len();
    let package_info = build_package_info(&manifests);

    let output_model = Output {
        package_info,
        module_name,
        cargo_toml_path,
        num_of_cargo_toml,
    };

    write_output(output, &output_model)
}

#[derive(Debug)]
struct CargoManifestInfo {
    rel_path: String,
    package_name: Option<String>,
}

fn discover_cargo_toml(root_dir: &Path) -> Result<Vec<CargoManifestInfo>, RunError> {
    let mut found_paths = Vec::new();
    walk_for_cargo_toml(root_dir, &mut found_paths)?;
    let mut manifests = Vec::with_capacity(found_paths.len());
    for manifest_path in found_paths {
        let rel_path = manifest_rel_path(root_dir, &manifest_path);
        let package_name = parse_package_name_from_manifest(&manifest_path)?;
        manifests.push(CargoManifestInfo {
            rel_path,
            package_name,
        });
    }
    Ok(manifests)
}

fn walk_for_cargo_toml(dir: &Path, found_paths: &mut Vec<PathBuf>) -> Result<(), RunError> {
    let entries = fs::read_dir(dir).map_err(|source| RunError::Io {
        context: format!("failed to read directory {}", dir.display()),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| RunError::Io {
            context: format!("failed to read directory entry in {}", dir.display()),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| RunError::Io {
            context: format!("failed to inspect file type {}", path.display()),
            source,
        })?;

        if file_type.is_dir() {
            if should_skip_dir(path.file_name()) {
                continue;
            }
            walk_for_cargo_toml(&path, found_paths)?;
            continue;
        }

        if file_type.is_file() && path.file_name() == Some(OsStr::new(CARGO_TOML_FILE_NAME)) {
            found_paths.push(path);
        }
    }

    Ok(())
}

fn should_skip_dir(name: Option<&OsStr>) -> bool {
    let Some(name) = name.and_then(OsStr::to_str) else {
        return false;
    };
    if name.starts_with('.') {
        return true;
    }
    matches!(name, "target" | "node_modules" | "vendor" | ".venv")
}

fn manifest_rel_path(root_dir: &Path, manifest_path: &Path) -> String {
    let rel = manifest_path
        .strip_prefix(root_dir)
        .expect("discovered manifest should be inside root_dir");
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    format!("/{rel_str}")
}

fn parse_package_name_from_manifest(manifest_path: &Path) -> Result<Option<String>, RunError> {
    let content = fs::read_to_string(manifest_path).map_err(|source| RunError::Io {
        context: format!("failed to read manifest {}", manifest_path.display()),
        source,
    })?;

    let value = match toml::from_str::<toml::Value>(&content) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let name = value
        .get("package")
        .and_then(|v| v.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    Ok(name)
}

fn build_package_info(manifests: &[CargoManifestInfo]) -> PackagePathInfo {
    let mut root = PackagePathInfo::empty_root();
    for manifest in manifests {
        insert_manifest_into_tree(&mut root, manifest);
    }
    root
}

fn insert_manifest_into_tree(root: &mut PackagePathInfo, manifest: &CargoManifestInfo) {
    let mut node = root;
    let parts: Vec<&str> = manifest
        .rel_path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return;
    }
    for part in &parts[..parts.len().saturating_sub(1)] {
        node = node
            .subs
            .entry((*part).to_string())
            .or_insert_with(|| PackagePathInfo {
                path_name: (*part).to_string(),
                files: BTreeMap::new(),
                subs: BTreeMap::new(),
            });
    }

    let package_name = manifest
        .package_name
        .clone()
        .unwrap_or_else(|| UNKNOWN_MODULE_NAME.to_string());
    node.files.insert(
        manifest.rel_path.clone(),
        NodeInfo {
            node: CompileUnit::empty(manifest.rel_path.clone()),
            package_name,
        },
    );
}

fn write_output(output_path: &Path, output: &Output) -> Result<(), RunError> {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| RunError::Io {
                context: format!("failed to create output directory {}", parent.display()),
                source,
            })?;
        }
    }

    let json = serde_json::to_vec(output).map_err(|source| RunError::Serialize { source })?;
    fs::write(output_path, json).map_err(|source| RunError::Io {
        context: format!("failed to write output {}", output_path.display()),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_expected_flags() {
        let args = vec![
            "-rootDir",
            "/tmp/example.rs",
            "-output",
            "/tmp/output.json",
            "-single",
        ];
        let cli = parse_args_from(args).expect("parse args");
        assert_eq!(cli.root_dir, PathBuf::from("/tmp/example.rs"));
        assert_eq!(cli.output, PathBuf::from("/tmp/output.json"));
        assert!(cli.single);
    }

    #[test]
    fn parse_args_rejects_missing_required_flags() {
        let args = vec!["-rootDir", "/tmp/example.rs"];
        let err = parse_args_from(args).expect_err("missing output should fail");
        assert!(matches!(err, ParseArgsError::Message(_)));
        assert!(err.to_string().contains("-output"));
    }

    #[test]
    fn parse_args_rejects_flag_as_value() {
        let args = vec!["-rootDir", "-output", "-output", "/tmp/out.json"];
        let err = parse_args_from(args).expect_err("flag used as value should fail");
        assert!(matches!(err, ParseArgsError::Message(_)));
        assert!(err.to_string().contains("Missing value for '-rootDir'"));
    }

    #[test]
    fn parse_package_name_reads_package_section_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manifest = temp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[workspace]\nmembers=[\"a\"]\n\n[package]\nname = \"demo_name\"\nversion = \"0.1.0\"\n",
        )
        .expect("write manifest");

        let name = parse_package_name_from_manifest(&manifest)
            .expect("parse manifest")
            .expect("package name");
        assert_eq!(name, "demo_name");
    }

    #[test]
    fn parse_package_name_keeps_hash_inside_quoted_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manifest = temp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"foo#bar\" # trailing comment\nversion = \"0.1.0\"\n",
        )
        .expect("write manifest");

        let name = parse_package_name_from_manifest(&manifest)
            .expect("parse manifest")
            .expect("package name");
        assert_eq!(name, "foo#bar");
    }
}
