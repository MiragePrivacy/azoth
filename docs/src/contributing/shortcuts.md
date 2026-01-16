# Shortcuts

Handy commands while iterating locally:

- `cargo run -p azoth-cli -- decode 0x...` — quick opcode inspection.
- `cargo run -p azoth-cli -- obfuscate <HEX> --seed 0xdeadbeef --passes shuffle,jump_transform` — dry-run a transform combo deterministically.
- `cargo test -p azoth-core --lib` — run core unit tests without touching the rest of the workspace.
- `cargo test -p azoth-transform --all-targets` — exercise transform logic plus property tests.
- `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` — one-liner style/lint check before committing.
- `cargo doc --workspace --no-deps --open` — build rustdoc for all crates to cross-check API descriptions against this book.
