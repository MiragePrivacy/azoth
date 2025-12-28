# Program Analysis

`azoth-analysis` computes quantitative metrics before and after each obfuscation pass so we can reason about size, CFG complexity, and stack pressure. Transforms and the CLI use these measurements to decide whether a candidate rewrite is worth keeping.

## Metrics collected

`metrics::collect_metrics` consumes a `CfgIrBundle` plus the `CleanReport` from `strip::strip_bytecode` and returns:

- `byte_len` – length of the cleaned runtime.
- `block_cnt` / `edge_cnt` – number of body blocks and edges in the CFG (entry/exit excluded).
- `max_stack_peak` – maximum recorded stack height across blocks.
- `dom_overlap` – fraction of nodes whose immediate dominator equals their immediate post-dominator (lower overlap ⇒ less linear control flow).
- `potency` – heuristic score derived from block/edge counts and dominator overlap (based on Wroblewski’s potency metric).

Consumers can compare two metric snapshots via `metrics::compare`, which highlights potency gains while accounting for bytecode growth. The CLI’s `obfuscate` subcommand prints these deltas after each run.

## Dominator utilities

The crate also exposes helpers such as `dominator_pairs`, `dom_overlap`, and `max_stack_per_block`. They are useful when you need deeper inspection during transform development or custom acceptance heuristics (e.g., rejecting passes that blow past a stack threshold).
