# Azoth
![Azoth](assets/azoth.jpg)

## What is Azoth?

Azoth is an open-source bytecode camouflage tool for Ethereum smart contracts. It changes recognizable features of compiled code, such as how the contract routes function calls, while aiming to preserve its behavior. With the same input, settings, and seed, you can reproduce the output and check it against a deployment.

Mirage uses Azoth so that its one-time escrows don’t all publish the same bytecode. Without that variation, an exact match against one known deployment could flag other escrows using the template. Camouflage addresses that signal while keeping the deployment reproducible. Observers can still examine shared patterns and onchain behavior. Mirage’s [zero-knowledge settlement proofs](https://docs.mirageprivacy.com/developers/technical-model#settlement-proofs) keep payment evidence private even when an escrow is recognized.

## How does it work?

1. **Read the bytecode.** Azoth identifies the creation and runtime code and maps the paths the contract can take.
2. **Apply transforms.** The seed guides changes to the bytecode, such as varying how the contract dispatches function calls.
3. **Reassemble the deployment.** Azoth rebuilds the bytecode and checks its structure. The project also includes tools to compare behavior before and after a transformation.

Azoth can mask constructor arguments in the creation bytecode. The public code still contains enough information to recover those arguments. See the [constructor-argument report](docs/constructor-argument-camouflage.md) for details.

## Status

Azoth is under active development: the parsing pipeline, CFG builder, and several core transforms are in daily use, while additional passes, verification tooling, and resilience metrics are landing incrementally as we harden the stack for production-facing deployments.

## Getting Started

Run `cargo run --bin azoth -- camouflage --help` to see how to supply deployment bytecode, a seed, and transform settings. The [CLI guide](crates/cli/README.md) walks through an example. Existing scripts can still use the `obfuscate` command alias.

## Fuzzing

Azoth includes a built-in fuzzer for testing the camouflage pipeline. The fuzzer generates random seeds and transform combinations, running them against test contracts to discover edge cases and potential issues.

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

# Enable deployment verification (checks camouflaged bytecode deploys correctly)
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
| `--check-deploy` | Verify camouflaged bytecode deploys successfully via REVM |

## Contributing

We welcome new transforms, analysis improvements, performance tuning, documentation, and bug fixes. See [CONTRIBUTING.md](CONTRIBUTING.md) for style and workflow guidelines.

## Acknowledgments
Azoth builds on years of research in program analysis, camouflage, and blockchain privacy. We are grateful to the broader community whose work makes this project possible.
