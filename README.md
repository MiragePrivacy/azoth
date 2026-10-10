# Azoth
![Azoth](assets/azoth.jpg)

## What is Azoth?

Azoth is a deterministic EVM bytecode obfuscator that varies deployment and runtime bytecode while preserving the behavior of supported contracts. Its research goal is to reduce static linkability and make transformed contracts resemble the broad population of unverified Ethereum deployments. Indistinguishability is an evaluation target, not a guarantee. The name "[Azoth](https://www.wikiwand.com/en/articles/Azoth)" derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as the essential agent of transformation.

## How does it work?

1. Dissection: decode the contract’s init/runtime layout, resolve sections, and build a control-flow graph of block bodies and jump targets.

2. Transformation: apply seed-derived passes transactionally. The production default is selector-only `FunctionDispatcher` when a supported dispatcher is detected, followed by low-density `JumpTrampoline` topology diversification and LCS-bounded `ClusterShuffle` layout diversification.

3. Recovery: lower the rewritten runtime, patch init-code offsets, and mask any exact constructor-argument suffix so the final bytecode stays deployable without retaining an ABI-aligned plaintext tail.

The verification crate is experimental scaffolding. Contract-equivalence entry points currently return `Unsupported`; Azoth does not provide a formal proof or mathematical guarantee of semantic equivalence. Safety must instead be established with compiler-specific differential deployment and behavioral tests for the exact contract and pass set.

Constructor-argument masking is an obfuscation boundary, not encryption: it defeats verbatim static suffix recovery, but public creation code can still be analyzed or executed to recover values. See the [constructor-argument security and benchmark report](docs/constructor-argument-obfuscation.md).

## Status

Azoth is under active development. The current pipeline fails closed for unsupported self-code-layout and gas-observation patterns, including all `EXTCODE*` introspection because its target may alias the current contract, as well as ambiguous dispatcher selector uses, unsupported constructor layouts, and EVM size-limit violations. Those guards reduce known risks but do not establish equivalence for arbitrary bytecode. Treat generated deployments as experimental until they pass contract-specific differential tests.

The optional JSON report records byte sizes and exact EVM code-deposit gas for the deployed runtime (`200 gas/byte`). It deliberately does not estimate creation calldata cost, EIP-3860 word cost, constructor execution, or runtime execution gas; measure those with an EVM harness.

The current hardening results, benchmark methodology, red-team findings, and remaining limitations are documented in the [technical report](docs/AZOTH_TECHNICAL_REPORT.md) and [executive report](docs/AZOTH_EXECUTIVE_REPORT.md).

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
