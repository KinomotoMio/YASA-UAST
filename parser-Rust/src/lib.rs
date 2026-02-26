mod model;

use clap::{error::ErrorKind, Parser};
pub use model::{CompileUnit, NodeInfo, Output, PackagePathInfo, LANGUAGE};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const SINGLE_FILE_PACKAGE_NAME: &str = "__single__";
const SINGLE_FILE_MODULE_NAME: &str = "__single_module__";
const UNKNOWN_MODULE_NAME: &str = "__unknown_module__";

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "uast4rust",
    disable_help_subcommand = true,
    override_usage = "uast4rust -rootDir <path> -output <path> [-single]"
)]
pub struct CliArgs {
    #[arg(long = "rootDir", value_name = "path")]
    pub root_dir: PathBuf,
    #[arg(long = "output", value_name = "path")]
    pub output: PathBuf,
    #[arg(long = "single", default_value_t = false)]
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
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Serialize { source } => write!(f, "failed to serialize output json: {source}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInputPath { .. } => None,
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
    let mut argv = vec!["uast4rust".to_string()];
    argv.extend(args.into_iter().map(Into::into).map(normalize_legacy_flag));

    match CliArgs::try_parse_from(argv) {
        Ok(cli) => Ok(cli),
        Err(err) => match err.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                Err(ParseArgsError::HelpRequested)
            }
            _ => Err(ParseArgsError::Message(err.to_string())),
        },
    }
}

pub fn parse_args() -> Result<CliArgs, ParseArgsError> {
    parse_args_from(env::args().skip(1))
}

fn normalize_legacy_flag(arg: String) -> String {
    match arg.as_str() {
        "-rootDir" => "--rootDir".to_string(),
        "-output" => "--output".to_string(),
        "-single" => "--single".to_string(),
        _ => arg,
    }
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
        assert!(err.to_string().contains("output"));
    }
}
