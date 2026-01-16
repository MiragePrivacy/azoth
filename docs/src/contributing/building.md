# Building

Azoth uses a pinned stable toolchain (`rust-toolchain.toml` requests Rust 1.90.0 plus rustfmt and clippy). Install via `rustup` if you have not already:

```bash
rustup toolchain install 1.90.0 --component rustfmt --component clippy
```

## Compile the workspace

```bash
cargo build --workspace
```

This command builds every crate (core, transforms, analysis, CLI, verification, examples, tests). Add `--release` if you want optimised binaries.

### Building individual crates

- Core library only: `cargo build -p azoth-core`
- CLI binary: `cargo build -p azoth-cli --bin azoth`
- Example workflow: `cargo run -p azoth-examples`

The build pulls dependencies such as Heimdall, REVM, and SMT utilities; make sure you have network access the first time you compile.

## Formatting and linting

Run formatting and clippy before submitting a change:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

Both commands use the pinned toolchain, keeping CI and local development consistent.
