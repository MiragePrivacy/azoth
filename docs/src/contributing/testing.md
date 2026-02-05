# Testing

Azoth ships with unit tests inside each crate plus an integration test crate under `tests/`. To run everything:

```bash
cargo test --workspace
```

### Targeted suites

- Core strip/detection/CFG tests: `cargo test -p azoth-core`
- Analysis metrics: `cargo test -p azoth-analysis`
- Transform behaviour: `cargo test -p azoth-transform`
- CLI smoke tests: `cargo test -p azoth-cli`
- Multi-crate integration (escrow fixtures, e2e): `cargo test -p azoth-tests`

Several transform tests rely on determinism. When adding new passes, seed the RNG explicitly (`StdRng::seed_from_u64`) so assertions stay stable on CI.

### Additional checks

Use `cargo clippy --workspace --all-targets -- -D warnings` to catch lints and `cargo fmt --all` to enforce formatting prior to submitting a PR.
