# Azoth CLI

The `azoth-cli` crate provides the command-line interface for the Azoth EVM bytecode camouflage tool. This crate offers a simple set of tools for analyzing, transforming, and camouflaging Ethereum smart contract bytecode.

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
azoth decode -D <DEPLOYMENT_BYTECODE>
azoth decode --deployment 0x608060405234801561001057600080fd5b50
azoth decode -D path/to/bytecode.hex
```

Outputs the raw assembly from Heimdall disassembler followed by a list of instructions with program counters and opcodes.

### `azoth strip`
Extracts runtime bytecode from deployment bytecode, removing init code and auxdata.

```bash
azoth strip -D <DEPLOYMENT_BYTECODE> -R <RUNTIME_BYTECODE>
azoth strip --deployment 0x608060405234801561001057600080fd5b50 --runtime 0x6080...
azoth strip -D path/to/deployment.hex -R path/to/runtime.hex --raw
```

Options:
- `-D, --deployment <BYTECODE>` - Input deployment bytecode (required)
- `-R, --runtime <BYTECODE>` - Input runtime bytecode (required)
- `--raw` - Output raw cleaned runtime hex instead of JSON report

### `azoth cfg`
Generates a Graphviz .dot file representing the control flow graph.

```bash
azoth cfg -D <DEPLOYMENT_BYTECODE> -R <RUNTIME_BYTECODE>
azoth cfg --deployment 0x6080... --runtime 0x6080... --output graph.dot
azoth cfg -D path/to/deployment.hex -R path/to/runtime.hex
```

Options:
- `-D, --deployment <BYTECODE>` - Input deployment bytecode (required)
- `-R, --runtime <BYTECODE>` - Input runtime bytecode (required)
- `-o, --output <file>` - Write .dot file to specified path (default: stdout)

### `azoth camouflage`
Applies camouflage transformations to bytecode.

```bash
azoth camouflage -D <DEPLOYMENT_BYTECODE> -R <RUNTIME_BYTECODE>
azoth camouflage --deployment 0x6080... --runtime 0x6080... --seed 12345
azoth camouflage -D path/to/deployment.hex -R path/to/runtime.hex --passes shuffle
azoth camouflage -D path/to/deployment.hex -R path/to/runtime.hex --constructor-args 0x...
```

Options:
- `-D, --deployment <BYTECODE>` - Input deployment bytecode (required)
- `-R, --runtime <BYTECODE>` - Input runtime bytecode (required)
- `--constructor-args <HEX>` - ABI-encoded constructor suffix to append and camouflage; omit when `-D` already contains it
- `--seed <value>` - Cryptographic seed for deterministic camouflage
- `--passes <list>` - Comma-separated list of transforms (default: shuffle)
- `--emit <file>` - Path to write gas/size report as JSON
- `--emit-debug <PATH>` - Path to emit detailed CFG trace debug report as JSON
- `--tui` - Launch TUI to view debug trace after camouflage

Note: `function_dispatcher` is always applied automatically.

The runtime is used as an exact, authoritative deployment boundary. A supplied runtime that is missing or occurs more than once is rejected. Constructor masking does not parse the ABI and is not cryptographic confidentiality; it removes the stable plaintext suffix while preserving constructor behavior.

### `azoth analyze`
Generates multiple camouflaged variants and reports how much of the original bytecode survives unchanged.

```bash
azoth analyze <ITERATIONS> -D <DEPLOYMENT_BYTECODE> -R <RUNTIME_BYTECODE>
azoth analyze 50 --deployment path/to/deployment.hex --runtime path/to/runtime.hex
azoth analyze 25 -D 0x6080... -R 0x6080... --output reports/analysis.md
```

Options:
- `-D, --deployment <BYTECODE>` - Input deployment bytecode (default: examples/escrow-bytecode/artifacts/erc20_deployment.hex)
- `-R, --runtime <BYTECODE>` - Input runtime bytecode (default: examples/escrow-bytecode/artifacts/erc20_runtime.hex)
- `--output <path>` - Where to write the markdown report (default: ./camouflage_analysis_report.md)
- `--max-attempts <n>` - Retry budget per iteration when a seed fails (default: 5)

The analysis runs with the dispatcher when detected and otherwise mirrors the camouflage tool's default transform selection (no extra passes are forced). The summary printed to stdout mirrors the generated report and includes average/percentile longest preserved block sizes plus n-gram diversity metrics.

## Input Formats

The CLI supports:

1. **Hex String** - Direct bytecode: `0x608060405234801561001057600080fd5b50`
2. **File Path** - File containing bytecode: `path/to/bytecode.hex`

For `.hex` files, the content should be hex-encoded bytecode (with or without 0x prefix).
