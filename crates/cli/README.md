# Azoth CLI

The `azoth-cli` crate provides the command-line interface for the Azoth EVM bytecode obfuscator. This crate offers a simple set of tools for analyzing, transforming, and obfuscating Ethereum smart contract bytecode.

## Installation

```bash
# Install from source
cd crates/cli
cargo install --path .

# Or build binary
cargo build --release --bin azoth
```

## Commands

### `azoth decode`
Decodes EVM bytecode into human-readable instruction format.

```bash
azoth decode <INPUT>
azoth decode 0x608060405234801561001057600080fd5b50
azoth decode path/to/bytecode.hex
```

Outputs the raw assembly from Heimdall disassembler followed by a list of instructions with program counters and opcodes.

### `azoth strip`
Extracts runtime bytecode from deployment bytecode, removing init code and auxdata.

```bash
azoth strip <INPUT>
azoth strip 0x608060405234801561001057600080fd5b50
azoth strip --raw path/to/bytecode.hex
```

Options:
- `--raw` - Output raw cleaned runtime hex instead of JSON report

### `azoth cfg`
Generates a Graphviz .dot file representing the control flow graph.

```bash
azoth cfg <INPUT>
azoth cfg --output graph.dot 0x608060405234801561001057600080fd5b50
```

Options:
- `--output <file>` - Write .dot file to specified path (default: stdout)

### `azoth obfuscate`
Applies obfuscation transformations to bytecode.

```bash
azoth obfuscate <INPUT>
azoth obfuscate --seed 12345 0x608060405234801561001057600080fd5b50
azoth obfuscate --passes shuffle,jump_transform path/to/bytecode.hex
```

Options:
- `--seed <value>` - Random seed for transform application (default: 42)
- `--passes <list>` - Comma-separated list of transforms (default: shuffle,jump_transform,opaque_pred)
- `--accept-threshold <value>` - Minimum quality threshold for accepting transforms (default: 0.0)
- `--max-size-delta <fraction>` - Maximum allowable size increase (default: 0.1)
- `--emit <file>` - Path to write gas/size report as JSON

Available transforms: `shuffle`, `jump_transform`, `opaque_pred`

Note: `function_dispatcher` is always applied automatically.

### `azoth analyze`
Generates multiple obfuscated variants and reports how much of the original bytecode survives unchanged.

```bash
azoth analyze <ITERATIONS>
azoth analyze 50 examples/escrow-bytecode/artifacts/runtime_bytecode.hex
azoth analyze 25 0x608060405234801561001057600080fd5b50 --output reports/analysis.md
```

Options:
- `--output <path>` - Where to write the markdown report (default: ./obfuscation_analysis_report.md)
- `--max-attempts <n>` - Retry budget per iteration when a seed fails (default: 5)

The analysis always runs with the dispatcher (when detected) plus the shuffle transform, matching the shell script behaviour. The summary printed to stdout mirrors the generated report and includes average/percentile longest preserved block sizes plus n-gram diversity metrics.

## Input Formats

The CLI supports:

1. **Hex String** - Direct bytecode: `0x608060405234801561001057600080fd5b50`
2. **File Path** - File containing bytecode: `path/to/bytecode.hex`

For `.hex` files, the content should be hex-encoded bytecode (with or without 0x prefix).
