mod model;

pub use model::{CompileUnit, NodeInfo, Output, PackagePathInfo, LANGUAGE};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const SINGLE_FILE_PACKAGE_NAME: &str = "__single__";
const SINGLE_FILE_MODULE_NAME: &str = "__single_module__";
const UNKNOWN_MODULE_NAME: &str = "__unknown_module__";

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

    let output_model = Output {
        package_info: PackagePathInfo::empty_root(),
        module_name: UNKNOWN_MODULE_NAME.to_string(),
        cargo_toml_path: String::new(),
        num_of_cargo_toml: 0,
    };

    write_output(output, &output_model)
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
}
