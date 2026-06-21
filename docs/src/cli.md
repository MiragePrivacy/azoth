# Command Line Interface

The `azoth` binary (crate `azoth-cli`) exposes the full pipeline from the terminal. Install with `cargo install --path crates/cli` or run in-place via `cargo run -p azoth-cli -- <command>`.

## Shared conventions

- Inputs accept either a hex literal (with or without `0x`) or a path to a `.hex`/binary file.
- Output is printed to stdout unless an explicit `--output`/`--emit` flag is provided.
- All commands normalise whitespace and underscores in hex payloads.

## Subcommands

- `azoth decode <INPUT>`  
  Runs the Heimdall disassembler and prints annotated assembly plus the structured instruction list. Useful for quick inspection or seeding tests.

- `azoth strip <INPUT> [--raw]`  
  Removes init code, constructor args, padding, and auxdata. By default it emits a JSON payload mirroring `strip::CleanReport`; pass `--raw` to dump just the cleaned runtime hex.

- `azoth cfg <INPUT> [--output <path>]`  
  Builds the runtime CFG and writes a Graphviz `.dot` representation (stdout by default). Pair with `dot -Tpng` for visualisation.

- `azoth obfuscate <INPUT> [--seed HEX] [--passes list] [--emit path] [--emit-debug path]`  
  Executes the unified obfuscation pipeline. The optional `--seed` fixes RNG output (deterministic replays); `--passes` controls the user-facing transforms (default `shuffle,jump_transform,opaque_pred`). When a Solidity dispatcher is detected the hardened dispatcher transform runs automatically. `--emit` writes gas/size metrics to JSON, and `--emit-debug` exports the recorded CFG trace.

Each command returns a non-zero exit code on failure, so you can integrate the CLI into scripts or CI jobs easily.
