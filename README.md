# Azoth
![Azoth](assets/azoth.jpg)

## What is Azoth?

Azoth is a deterministic EVM bytecode obfuscator designed to make Mirage's execution contracts indistinguishable from ordinary, unverified deployments on Ethereum. The name "[Azoth](https://www.wikiwand.com/en/articles/Azoth)" derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as the essential agent of transformation.

## How does it work?

1. Dissection: decode the contract’s init/runtime layout, resolve sections, and build a control-flow graph of block bodies and jump targets.

2. Transformation: apply deterministic transformations (e.g dispatcher transforms, block shuffling etc.) that changes the structure of the bytecode without blowing gas or size limits.

3. Recovery: lower the rewritten runtime alongside untouched init/constructor data so the final bytecode stays deployable.

Azoth also incorporates a formal verification system that provides mathematical guarantees of functional equivalence between original and obfuscated contracts.

## Status

Azoth is under active development: the parsing pipeline, CFG builder, and several core transforms are in daily use, while additional passes, verification tooling, and resilience metrics are landing incrementally as we harden the stack for production-facing deployments.

## Getting Started

Azoth is available through a command-line interface. This could be used for local development, testing, and experimentation with bytecode obfuscation.

## Fuzzing

Azoth includes a built-in fuzzer for testing the obfuscation pipeline. The fuzzer generates random seeds and transform combinations, running them against test contracts to discover edge cases and potential issues.

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

# Enable deployment verification (checks obfuscated bytecode deploys correctly)
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
| `--check-deploy` | Verify obfuscated bytecode deploys successfully via REVM |

## Contributing

We welcome new transforms, analysis improvements, performance tuning, documentation, and bug fixes. See [CONTRIBUTING.md](CONTRIBUTING.md) for style and workflow guidelines.

## Acknowledgments
Azoth builds on years of research in program analysis, obfuscation, and blockchain privacy. We are grateful to the broader community whose work makes this project possible.
