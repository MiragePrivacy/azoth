# Azoth examples

Run the escrow example to see how Azoth transforms a Mirage deployment and compares it with the original.

```bash
bash examples/run_escrow.sh
```

The script uses the ERC-20 deployment and runtime artifacts from the escrow submodule. It initializes the pinned submodule if those files are missing. The example writes its bytecode, gas, and behavior comparison to `examples/mirage_report.json`.
