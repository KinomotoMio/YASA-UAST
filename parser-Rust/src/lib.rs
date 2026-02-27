mod model;

pub use model::{CompileUnit, NodeInfo, Output, PackagePathInfo, LANGUAGE};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use syn::{
    BinOp, Expr, ExprAssign, ExprBinary, ExprCall, ExprField, ExprLit, ExprMethodCall, ExprPath,
    ExprReturn, Field, Fields, FnArg, Item, ItemFn, ItemStruct, Lit, Local, Pat, ReturnType, Stmt,
    Type, Visibility,
};

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
    ParseSource {
        path: PathBuf,
        source: syn::Error,
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
            Self::ParseSource { path, source } => {
                write!(
                    f,
                    "failed to parse rust source {}: {}",
                    path.display(),
                    source
                )
            }
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
            Self::ParseSource { source, .. } => Some(source),
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

    let source = fs::read_to_string(file).map_err(|source| RunError::Io {
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
    let parsed_file = syn::parse_file(&source).map_err(|source| RunError::ParseSource {
        path: file.to_path_buf(),
        source,
    })?;
    let compile_unit = lower_single_file_uast(&parsed_file, file_key.clone());
    let mut files = BTreeMap::new();
    files.insert(
        file_key.clone(),
        NodeInfo {
            node: compile_unit,
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

fn lower_single_file_uast(file: &syn::File, uri: String) -> CompileUnit {
    let mut unit = CompileUnit::empty(uri);
    unit.body = file.items.iter().filter_map(lower_item).collect();
    unit
}

fn lower_item(item: &Item) -> Option<Value> {
    match item {
        Item::Fn(item_fn) => Some(lower_function(item_fn)),
        Item::Struct(item_struct) => Some(lower_struct(item_struct)),
        _ => None,
    }
}

fn lower_function(item_fn: &ItemFn) -> Value {
    let parameters = item_fn
        .sig
        .inputs
        .iter()
        .map(lower_fn_arg)
        .collect::<Vec<_>>();
    let return_type = lower_return_type(&item_fn.sig.output);
    let body = scoped_statement(item_fn.block.stmts.iter().filter_map(lower_stmt).collect());

    json!({
        "type": "FunctionDefinition",
        "id": identifier(item_fn.sig.ident.to_string()),
        "parameters": parameters,
        "returnType": return_type,
        "body": body,
        "modifiers": function_modifiers(item_fn),
    })
}

fn function_modifiers(item_fn: &ItemFn) -> Vec<String> {
    let mut modifiers = Vec::new();
    if matches!(item_fn.vis, Visibility::Public(_)) {
        modifiers.push("pub".to_string());
    }
    if item_fn.sig.constness.is_some() {
        modifiers.push("const".to_string());
    }
    if item_fn.sig.asyncness.is_some() {
        modifiers.push("async".to_string());
    }
    if item_fn.sig.unsafety.is_some() {
        modifiers.push("unsafe".to_string());
    }
    modifiers
}

fn lower_struct(item_struct: &ItemStruct) -> Value {
    let body = match &item_struct.fields {
        Fields::Named(named) => named
            .named
            .iter()
            .map(lower_struct_field)
            .collect::<Vec<_>>(),
        Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .map(|(idx, field)| lower_unnamed_struct_field(idx, field))
            .collect::<Vec<_>>(),
        Fields::Unit => Vec::new(),
    };

    json!({
        "type": "ClassDefinition",
        "id": identifier(item_struct.ident.to_string()),
        "body": body,
        "supers": [],
    })
}

fn lower_struct_field(field: &Field) -> Value {
    let name = field
        .ident
        .as_ref()
        .map(|ident| ident.to_string())
        .unwrap_or_else(|| "__field__".to_string());
    variable_declaration(identifier(name), None, lower_type(&field.ty), false, false)
}

fn lower_unnamed_struct_field(index: usize, field: &Field) -> Value {
    variable_declaration(
        identifier(format!("_{index}")),
        None,
        lower_type(&field.ty),
        false,
        false,
    )
}

fn lower_fn_arg(arg: &FnArg) -> Value {
    match arg {
        FnArg::Typed(pat_ty) => {
            let name = extract_binding_name(&pat_ty.pat).unwrap_or_else(|| "__param__".to_string());
            variable_declaration(identifier(name), None, lower_type(&pat_ty.ty), false, false)
        }
        FnArg::Receiver(_) => Value::Null,
    }
}

fn lower_stmt(stmt: &Stmt) -> Option<Value> {
    match stmt {
        Stmt::Local(local) => lower_local(local),
        Stmt::Item(item) => lower_item(item),
        Stmt::Expr(expr, _) => lower_expr(expr),
        Stmt::Macro(_) => None,
    }
}

fn lower_local(local: &Local) -> Option<Value> {
    let (name, explicit_type) = extract_binding_name_and_type(&local.pat)?;
    let init = local
        .init
        .as_ref()
        .and_then(|local_init| lower_expr(&local_init.expr));
    let var_type = explicit_type.map(lower_type).unwrap_or_else(dynamic_type);
    let cloned = init.is_some();
    Some(variable_declaration(
        identifier(name),
        init,
        var_type,
        cloned,
        false,
    ))
}

fn lower_expr(expr: &Expr) -> Option<Value> {
    match expr {
        Expr::Path(expr_path) => Some(lower_path(expr_path)),
        Expr::Call(expr_call) => Some(lower_call(expr_call)),
        Expr::MethodCall(expr_method_call) => Some(lower_method_call(expr_method_call)),
        Expr::Field(expr_field) => Some(lower_field_access(expr_field)),
        Expr::Assign(expr_assign) => Some(lower_assignment(expr_assign)),
        Expr::Binary(expr_binary) => lower_binary(expr_binary),
        Expr::Return(expr_return) => Some(lower_return(expr_return)),
        Expr::Lit(expr_lit) => Some(lower_literal(expr_lit)),
        Expr::Paren(expr_paren) => lower_expr(&expr_paren.expr),
        Expr::Group(expr_group) => lower_expr(&expr_group.expr),
        _ => None,
    }
}

fn lower_path(expr_path: &ExprPath) -> Value {
    let mut segments = expr_path.path.segments.iter();
    let Some(first) = segments.next() else {
        return identifier("__path__");
    };

    let mut value = identifier(first.ident.to_string());
    for segment in segments {
        value = member_access(value, identifier(segment.ident.to_string()), false);
    }
    value
}

fn lower_call(expr_call: &ExprCall) -> Value {
    let callee = lower_expr(&expr_call.func).unwrap_or_else(|| identifier("__callee__"));
    let arguments = expr_call
        .args
        .iter()
        .map(|arg| lower_expr(arg).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    json!({
        "type": "CallExpression",
        "callee": callee,
        "arguments": arguments,
    })
}

fn lower_method_call(expr_method_call: &ExprMethodCall) -> Value {
    let object =
        lower_expr(&expr_method_call.receiver).unwrap_or_else(|| identifier("__receiver__"));
    let callee = member_access(
        object,
        identifier(expr_method_call.method.to_string()),
        false,
    );
    let arguments = expr_method_call
        .args
        .iter()
        .map(|arg| lower_expr(arg).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    json!({
        "type": "CallExpression",
        "callee": callee,
        "arguments": arguments,
    })
}

fn lower_field_access(expr_field: &ExprField) -> Value {
    let object = lower_expr(&expr_field.base).unwrap_or_else(|| identifier("__object__"));
    match &expr_field.member {
        syn::Member::Named(ident) => member_access(object, identifier(ident.to_string()), false),
        syn::Member::Unnamed(index) => {
            member_access(object, literal_number(index.index as i64), true)
        }
    }
}

fn lower_assignment(expr_assign: &ExprAssign) -> Value {
    let left = lower_expr(&expr_assign.left).unwrap_or_else(|| identifier("__lhs__"));
    let right = lower_expr(&expr_assign.right).unwrap_or_else(|| identifier("__rhs__"));
    json!({
        "type": "AssignmentExpression",
        "left": left,
        "right": right,
        "operator": "=",
        "cloned": true,
    })
}

fn lower_binary(expr_binary: &ExprBinary) -> Option<Value> {
    let operator = match &expr_binary.op {
        BinOp::Add(_) => "+",
        BinOp::Sub(_) => "-",
        BinOp::Mul(_) => "*",
        BinOp::Div(_) => "/",
        BinOp::Rem(_) => "%",
        BinOp::And(_) => "&&",
        BinOp::Or(_) => "||",
        BinOp::BitXor(_) => "^",
        BinOp::BitAnd(_) => "&",
        BinOp::BitOr(_) => "|",
        BinOp::Shl(_) => "<<",
        BinOp::Shr(_) => ">>",
        BinOp::Eq(_) => "==",
        BinOp::Lt(_) => "<",
        BinOp::Le(_) => "<=",
        BinOp::Ne(_) => "!=",
        BinOp::Ge(_) => ">=",
        BinOp::Gt(_) => ">",
        _ => return None,
    };
    let left = lower_expr(&expr_binary.left).unwrap_or_else(|| identifier("__left__"));
    let right = lower_expr(&expr_binary.right).unwrap_or_else(|| identifier("__right__"));
    Some(json!({
        "type": "BinaryExpression",
        "operator": operator,
        "left": left,
        "right": right,
    }))
}

fn lower_return(expr_return: &ExprReturn) -> Value {
    let argument = expr_return
        .expr
        .as_ref()
        .and_then(|expr| lower_expr(expr))
        .unwrap_or(Value::Null);
    json!({
        "type": "ReturnStatement",
        "argument": argument,
        "isYield": false,
    })
}

fn lower_literal(expr_lit: &ExprLit) -> Value {
    match &expr_lit.lit {
        Lit::Int(value) => match value.base10_parse::<i64>() {
            Ok(number) => literal_number(number),
            Err(_) => json!({
                "type": "Literal",
                "value": value.base10_digits(),
                "literalType": "number",
            }),
        },
        Lit::Float(value) => match value.base10_parse::<f64>() {
            Ok(number) => json!({
                "type": "Literal",
                "value": number,
                "literalType": "number",
            }),
            Err(_) => json!({
                "type": "Literal",
                "value": value.base10_digits(),
                "literalType": "number",
            }),
        },
        Lit::Bool(value) => json!({
            "type": "Literal",
            "value": value.value,
            "literalType": "boolean",
        }),
        Lit::Str(value) => json!({
            "type": "Literal",
            "value": value.value(),
            "literalType": "string",
        }),
        Lit::Char(value) => json!({
            "type": "Literal",
            "value": value.value().to_string(),
            "literalType": "string",
        }),
        _ => null_literal(),
    }
}

fn lower_return_type(return_type: &ReturnType) -> Value {
    match return_type {
        ReturnType::Default => void_type(),
        ReturnType::Type(_, ty) => {
            if let Type::Tuple(tuple) = ty.as_ref() {
                if tuple.elems.is_empty() {
                    return void_type();
                }
            }
            lower_type(ty)
        }
    }
}

fn lower_type(ty: &Type) -> Value {
    match ty {
        Type::Path(path) => dynamic_type_with_id(
            path.path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
        ),
        Type::Reference(reference) => lower_type(&reference.elem),
        Type::Tuple(tuple) if tuple.elems.is_empty() => void_type(),
        _ => dynamic_type(),
    }
}

fn extract_binding_name_and_type<'a>(pat: &'a Pat) -> Option<(String, Option<&'a Type>)> {
    match pat {
        Pat::Type(pat_type) => {
            let (name, _) = extract_binding_name_and_type(&pat_type.pat)?;
            Some((name, Some(pat_type.ty.as_ref())))
        }
        Pat::Ident(pat_ident) => Some((pat_ident.ident.to_string(), None)),
        Pat::Reference(pat_ref) => extract_binding_name_and_type(&pat_ref.pat),
        _ => None,
    }
}

fn extract_binding_name(pat: &Pat) -> Option<String> {
    extract_binding_name_and_type(pat).map(|(name, _)| name)
}

fn variable_declaration(
    id: Value,
    init: Option<Value>,
    var_type: Value,
    cloned: bool,
    variable_param: bool,
) -> Value {
    json!({
        "type": "VariableDeclaration",
        "id": id,
        "init": init.unwrap_or(Value::Null),
        "cloned": cloned,
        "varType": var_type,
        "variableParam": variable_param,
    })
}

fn identifier(name: impl Into<String>) -> Value {
    json!({
        "type": "Identifier",
        "name": name.into(),
    })
}

fn literal_number(value: i64) -> Value {
    json!({
        "type": "Literal",
        "value": value,
        "literalType": "number",
    })
}

fn null_literal() -> Value {
    json!({
        "type": "Literal",
        "value": Value::Null,
        "literalType": "null",
    })
}

fn member_access(object: Value, property: Value, computed: bool) -> Value {
    json!({
        "type": "MemberAccess",
        "object": object,
        "property": property,
        "computed": computed,
    })
}

fn scoped_statement(body: Vec<Value>) -> Value {
    json!({
        "type": "ScopedStatement",
        "body": body,
        "id": Value::Null,
    })
}

fn dynamic_type() -> Value {
    dynamic_type_with_id(None)
}

fn dynamic_type_with_id(id: Option<String>) -> Value {
    json!({
        "type": "DynamicType",
        "id": id.map(identifier).unwrap_or(Value::Null),
        "typeArguments": Value::Null,
    })
}

fn void_type() -> Value {
    json!({
        "type": "VoidType",
        "id": Value::Null,
        "typeArguments": Value::Null,
    })
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
