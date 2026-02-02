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

### `azoth obfuscate`
Applies obfuscation transformations to bytecode.

```bash
azoth obfuscate -D <DEPLOYMENT_BYTECODE> -R <RUNTIME_BYTECODE>
azoth obfuscate --deployment 0x6080... --runtime 0x6080... --seed 12345
azoth obfuscate -D path/to/deployment.hex -R path/to/runtime.hex --passes shuffle
```

Options:
- `-D, --deployment <BYTECODE>` - Input deployment bytecode (required)
- `-R, --runtime <BYTECODE>` - Input runtime bytecode (required)
- `--seed <value>` - Cryptographic seed for deterministic obfuscation
- `--passes <list>` - Comma-separated list of transforms (default: shuffle)
- `--emit <file>` - Path to write gas/size report as JSON
- `--emit-debug <PATH>` - Path to emit detailed CFG trace debug report as JSON
- `--tui` - Launch TUI to view debug trace after obfuscation

Note: `function_dispatcher` is always applied automatically.

### `azoth analyze`
Compare runtime bytecode against the Ethereum contracts dataset.

```bash
azoth analyze <RUNTIME_BYTECODE> --reindex --dataset-root <PATH_TO_DATASET> -block-start 20000000 --block-range 100000
```

Options:
- `--dataset-root <path>` - Override dataset root (default: ~/.azoth/datasets/ethereum_contracts)
- `--reindex` - Rebuild the dataset index before comparing
- `--block-start <block>` - Start block for filtered comparison
- `--block-range <blocks>` - Block range length for filtered comparison (required with `--block-start`)

## Input Formats

The CLI supports:

1. **Hex String** - Direct bytecode: `0x608060405234801561001057600080fd5b50`
2. **File Path** - File containing bytecode: `path/to/bytecode.hex`

For `.hex` files, the content should be hex-encoded bytecode (with or without 0x prefix).
