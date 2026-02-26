# uast4rust

`uast4rust` is the Rust parser binary for YASA-UAST.

## Build

```bash
cargo build --release
```

## Usage

Single-file mode:

```bash
./target/release/uast4rust -rootDir /path/to/file.rs -output /path/to/output.json -single
```

Project mode:

```bash
./target/release/uast4rust -rootDir /path/to/project -output /path/to/output.json
```
