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

Azoth is available through a command-line interface for local development, testing, and experimentation with bytecode obfuscation.

### Installation

Build the CLI from source:

```bash
cargo build --release --bin azoth
```

The binary will be available at `target/release/azoth`.

### Basic Usage

Azoth provides several commands for working with EVM bytecode. Input can be provided as a hex string (with or without `0x` prefix) or as a path to a file containing bytecode.

#### Decode Bytecode

Convert bytecode to human-readable assembly instructions:

```bash
azoth decode 0x608060405234801561001057600080fd5b50
azoth decode path/to/bytecode.hex
```

#### Strip Init Code and Auxdata

Extract runtime bytecode by removing initialization code and auxiliary data:

```bash
azoth strip 0x608060405234801561001057600080fd5b50
azoth strip --raw path/to/bytecode.hex
```

#### Generate Control Flow Graph

Create a Graphviz visualization of the bytecode control flow:

```bash
azoth cfg 0x608060405234801561001057600080fd5b50
azoth cfg --output graph.dot path/to/bytecode.hex
```

#### Obfuscate Bytecode

Apply obfuscation transforms to make bytecode harder to analyze:

```bash
azoth obfuscate --input path/to/deployment.hex --runtime path/to/runtime.hex
azoth obfuscate --input deploy.hex --runtime runtime.hex --seed 12345
azoth obfuscate --input deploy.hex --runtime runtime.hex --passes shuffle,jump_transform
```

Available transforms: `shuffle`, `jump_transform`, `opaque_pred`, `arithmetic_chain`, `push_split`, `storage_gates`, `slot_shuffle`, `cluster_shuffle`, `splice`. The `function_dispatcher` transform is always applied automatically when detected.

#### Analyze Obfuscation Quality

Generate multiple obfuscated variants and measure preservation of original bytecode:

```bash
azoth analyze 50 path/to/runtime.hex
azoth analyze 25 0x608060405234801561001057600080fd5b50 --output report.md
```

### Using the TUI (Terminal User Interface)

Azoth includes an interactive TUI for exploring obfuscation debug traces. The TUI provides a visual representation of how transforms modified the bytecode control flow graph.

There are two ways to launch the TUI:

#### Option 1: Direct Launch with `--tui`

Add the `--tui` flag to the obfuscate command to automatically launch the TUI after obfuscation completes:

```bash
azoth obfuscate --input deploy.hex --runtime runtime.hex --tui
```

#### Option 2: Save Debug File and Launch Separately

First, obfuscate bytecode and save the debug trace to a file:

```bash
azoth obfuscate --input deploy.hex --runtime runtime.hex --emit-debug debug.json
```

Then launch the TUI to explore the debug file:

```bash
azoth tui debug.json
```

This two-step approach is useful when you want to save debug traces for later analysis or share them with others.

### Additional Resources

For detailed information about CLI commands, options, and advanced usage patterns, see the [CLI documentation](crates/cli/README.md).

## Contributing

We welcome new transforms, analysis improvements, performance tuning, documentation, and bug fixes. See [CONTRIBUTING.md](CONTRIBUTING.md) for style and workflow guidelines.

## Acknowledgments
Azoth builds on years of research in program analysis, obfuscation, and blockchain privacy. We are grateful to the broader community whose work makes this project possible.
