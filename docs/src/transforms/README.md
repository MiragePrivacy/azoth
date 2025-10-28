# Transform Passes

Azoth’s transform crate wraps every obfuscation pass in a shared pipeline so we can mutate runtime bytecode deterministically and replay results with a fixed seed. The entry point is `obfuscator::obfuscate_bytecode`, which:

1. decodes input into CFG IR and section metadata via `azoth_core`,
2. detects whether a Solidity-style dispatcher is present,
3. applies the requested passes (plus dispatcher hardening when available),
4. records `TraceEvent`s for each change, and
5. reassembles deployable bytecode while tracking size/stack metrics.

Transforms implement the `Transform` trait (`fn name(&self) -> &'static str` and `fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool>`). A pass returns `true` when it actually changed the CFG, allowing the obfuscator to skip no-op metrics and keep acceptance logic simple. Errors bubble up through a shared `Error` enum that wraps core/encoder/metrics failures.

## Available passes

- **Function Dispatcher** (`function_dispatcher.rs`)  
  Automatically activated when the runtime contains a Solidity dispatcher. It remaps every selector to a keccak-derived token, updates jump tables and internal `PUSH4` call sites, and leaves overall layout untouched so downstream analysis still lines up with the original CFG structure.

- **Shuffle** (`shuffle.rs`)  
  Reorders basic blocks inside the runtime while preserving entry/exit edges. Every jump target is recalculated from the CFG, so layout changes without affecting correctness.

- **Jump Address Transformer** (`jump_address_transformer.rs`)  
  Replaces direct `PUSH <target>; JUMP/I` patterns with runtime arithmetic (e.g., split immediates plus `ADD`). This forces tooling to execute stack operations to recover destinations, complicating static recovery.

- **Opaque Predicate** (`opaque_predicate.rs`)  
  Injects always-true branches built from random constants and cheap arithmetic, inflating node/edge counts to confuse control-flow analysis while preserving fallthrough behaviour.

Additional passes can be added by implementing `Transform` and wiring them into the CLI/obfuscator config. Metrics from `azoth_analysis` are collected before and after each pass to gate acceptance thresholds in higher-level workflows.
