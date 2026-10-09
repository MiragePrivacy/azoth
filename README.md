# Azoth
![Azoth](assets/azoth.jpg)

## What is Azoth?

Azoth is an experimental deterministic EVM bytecode variation engine. Its design goal is to vary Mirage execution contracts while preserving supported EVM behavior, but the current safe profile has **not** demonstrated indistinguishability from ordinary unverified Ethereum deployments. The name "[Azoth](https://www.wikiwand.com/en/articles/Azoth)" derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as the essential agent of transformation.

## How does it work?

1. Dissection: decode the contract’s init/runtime layout, resolve sections, and build a control-flow graph of block bodies and jump targets.

2. Transformation: apply admitted deterministic transformations transactionally. The safe default currently admits relationship-aware cluster shuffling; experimental transforms require separate validation.

3. Recovery: lower the rewritten runtime, patch only proven init-code and immutable-reference locations, preserve compiler suffixes, and enforce EVM size limits. Constructor-argument and selector rewriting are disabled in the safe profile.

Formal equivalence verification is not available. The production-facing verifier fails closed with `VerificationUnavailable`; REVM deployment checks and differential tests are useful test evidence, not mathematical proof.

Disassembly in the production pipeline is native and synchronous. Azoth owns the legacy-EVM
opcode table and performs a one-pass byte walk; it does not invoke Heimdall or EOT. Heimdall remains
isolated in the analysis crate for optional decompiler/diff views. See the
[native decoder design](docs/native-bytecode-decoder.md) for fork scope, malformed-byte handling,
and the protocol-update checklist.

Constructor-argument masking is an obfuscation boundary, not encryption: it defeats verbatim static suffix recovery, but public creation code can still be analyzed or executed to recover values. See the [constructor-argument security and benchmark report](docs/constructor-argument-obfuscation.md).

## Status

Azoth is under active development and is not production-ready. Unsupported bytecode relationships and constructor shapes are rejected or produce an unchanged identity result. An unchanged result is safe fallback behavior, not evidence that a variation objective was achieved.

## Getting Started

Azoth is available through a command-line interface. This could be used for local development, testing, and experimentation with bytecode obfuscation.

## Fuzzing

Azoth includes a built-in deterministic parameter-campaign harness. A case index fixes its contract, seed, and transform subset, so worker scheduling does not change finite-run coverage. It currently covers the bundled escrow and counter fixtures; it is not an arbitrary-bytecode fuzzer.

### Basic Usage

```bash
# Run the fuzzer with default settings (uses all CPU cores)
cargo run --bin azoth -- fuzz

# Limit to 1000 iterations
cargo run --bin azoth -- fuzz -i 1000

# Run for 60 seconds
cargo run --bin azoth -- fuzz -d 60

# Use 4 parallel workers
cargo run --bin azoth -- fuzz -j 4

# Enable the REVM creation smoke check (not behavioral equivalence)
cargo run --bin azoth -- fuzz --check-deploy
```

### Crash Management

When the fuzzer discovers a failure, it saves a reproducible crash file to the `crashes/` directory (configurable via `--crash-dir`). Each crash file contains the seed, transform passes, and captured logs needed to reproduce the issue.

```bash
# List all saved crashes
cargo run --bin azoth -- fuzz list

# Replay a specific crash
cargo run --bin azoth -- fuzz replay crashes/crash_abc123.json
```

### Options

| Flag | Description |
|------|-------------|
| `-j, --jobs <N>` | Number of parallel workers (default: CPU cores) |
| `-i, --iterations <N>` | Maximum iterations, 0 for infinite (default: 0) |
| `-d, --duration <SECS>` | Maximum duration in seconds, 0 for infinite (default: 0) |
| `--crash-dir <PATH>` | Directory to save crash files (default: `crashes/`) |
| `--check-deploy` | Check that creation succeeds in REVM; this does not prove runtime behavior |

## Contributing

We welcome new transforms, analysis improvements, performance tuning, documentation, and bug fixes. See [CONTRIBUTING.md](CONTRIBUTING.md) for style and workflow guidelines.

## Acknowledgments
Azoth builds on years of research in program analysis, obfuscation, and blockchain privacy. We are grateful to the broader community whose work makes this project possible.
