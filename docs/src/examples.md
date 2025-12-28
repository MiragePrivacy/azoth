# Examples

The `examples/` crate demonstrates Azoth in a Mirage Protocol workflow. It pulls the escrow contract bytecode, applies the standard transform stack with a fixed seed, and validates determinism, size/gas overhead, and placeholder functional checks.

## Quick start

```bash
cd examples
chmod +x run_escrow.sh   # optional helper that refreshes the escrow submodule
cargo run                 # or ./run_escrow.sh to automate the steps
```

The binary loads `escrow-bytecode/artifacts/bytecode.hex`, runs `azoth_transform::obfuscator::obfuscate_bytecode` with shuffle/jump-address/opaque-predicate transforms, and writes a `mirage_report.json` summary containing:

- sizes before/after,
- applied transforms and unknown opcode counts,
- gas estimates derived from byte length, and
- deterministic recompilation checks.

Use this project as a template for integrating Azoth into larger build pipelines or for writing regression tests around specific contracts.
