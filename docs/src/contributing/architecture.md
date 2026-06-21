# Architecture

Azoth is organised as a collection of focused crates that share a common `azoth_core` foundation:

- `azoth_core` — decoding, section detection, bytecode stripping, CFG construction, and re-encoding. Every other crate consumes the data structures defined here.
- `azoth_transform` — transform trait implementations plus the orchestration pipeline (`obfuscator.rs`). Passes operate on `CfgIrBundle` and rely on `azoth_analysis` metrics to gauge impact.
- `azoth_analysis` — metrics (size, CFG complexity, stack peaks) and helper utilities (dominators). Used by transforms and the CLI to evaluate rewrites.
- `azoth_cli` — command-line interface exposing decode/strip/cfg/obfuscate workflows. It stitches the other crates together for end users.
- `azoth_verification` — formal verification scaffold that builds SMT queries to prove equivalence between original and obfuscated bytecode.
- `examples` — executable that demonstrates a full Mirage escrow obfuscation run, useful as an integration test bed.

`target/` isn’t checked in, so CI and local builds share the same cargo workspace semantics. New functionality typically lands in `azoth_core` first, then bubbles up through transforms, CLI, and docs.
