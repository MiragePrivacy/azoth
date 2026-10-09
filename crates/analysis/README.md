# Azoth Analysis

The `azoth-analysis` crate provides analytical metrics for evaluating EVM bytecode obfuscation transforms. This crate implements a minimal set of metrics to assess transform potency and gas efficiency.

## Architecture

The analysis crate focuses on quantifying bytecode complexity through:

1. **Control Flow Complexity** - Basic block and edge counts in the CFG
2. **Stack Usage** - Maximum stack height measurements  
3. **Dominator Analysis** - Control flow critical points using dominator/post-dominator overlap
4. **Size Metrics** - Bytecode length tracking
5. **Obfuscation Persistence** - Longest preserved byte sequences and n-gram diversity across randomized obfuscations
6. **Red-team Detection** - Linear-time opcode signatures, labelled-corpus metrics, and exact metadata linkage

## Key Components

### Metrics System (`metrics.rs`)

Implements core metrics for evaluating bytecode complexity and transformation effectiveness:

- **Bytecode Size** (`byte_len`) - Size of cleaned runtime bytecode in bytes
- **Block Count** (`block_cnt`) - Number of basic blocks in the CFG (excluding Entry/Exit)
- **Edge Count** (`edge_cnt`) - Number of edges in the CFG
- **Maximum Stack Peak** (`max_stack_peak`) - Maximum stack height across all body blocks
- **Dominator Overlap** (`dom_overlap`) - Fraction of nodes that are both dominators and post-dominators
- **Potency Score** (`potency`) - Composite score combining complexity metrics with overlap penalty

### Core Functions

The crate provides these primary functions:

- `collect_metrics(ir: &CfgIrBundle, report: &CleanReport) -> Result<Metrics, MetricsError>` - Collects all metrics from CFG and clean report
- `dominator_pairs(g: &DiGraph<Block, EdgeType, Ix>) -> (DominatorMap<Ix>, DominatorMap<Ix>)` - Computes dominator and post-dominator pairs
- `dom_overlap(doms: &DominatorMap<Ix>, pdoms: &DominatorMap<Ix>) -> f64` - Calculates dominator overlap fraction
- `compare(before: &Metrics, after: &Metrics) -> f64` - Compares metrics between transformations

### Metrics Structure

```rust
pub struct Metrics {
    pub byte_len: usize,
    pub block_cnt: usize, 
    pub edge_cnt: usize,
    pub max_stack_peak: usize,
    pub dom_overlap: f64,
    pub potency: f64,
}
```

The potency score uses the formula:
``` 
potency = 5.0 * log₂(nodes) + edges + 30.0 * (1.0 - overlap)
```

This balances control flow complexity against dominator overlap, with higher scores indicating greater obfuscation potential.

### Obfuscation Experiment (`obfuscation.rs`)

Runs multiple obfuscation attempts with deterministic child seeds derived from a required private
root seed and aggregates:

- Longest common preserved byte sequences per iteration  
- Summary statistics (average, median, percentiles, range, standard deviation)  
- Histogram distribution of preserved lengths  
- Top ten most frequent preserved sequences  
- N-gram diversity (n = 2, 4, 8) across obfuscated outputs

Use `AnalysisConfig` to configure iterations, transform passes, and output path, then call `analyze_obfuscation(config)` to produce a markdown report. The CLI subcommand `azoth analyze` builds on this module.

### Red-team detector (`detector.rs`)

The detector parses EVM instructions without treating PUSH immediates as opcodes and reports exact
dispatcher, push-split, arithmetic-chain, constructor-mask-decoder, tail-density,
malformed-bytecode, and terminal Solidity metadata features. It also runs cheap normalization
attacks: PUSH-immediate erasure, opcode-only basic-block sorting, and recognizable PushSplit
folding. Feature extraction is linear in bytecode size; sorting block fingerprints is
`O(blocks * log(blocks))`. The score is a stable heuristic, **not** a probability.
Detection-quality fields are emitted only when a corpus contains both labelled positives and
labelled negatives.

Run the standalone JSON harness with:

```bash
cargo run -p azoth-analysis --example detect_corpus -- corpus.json > detector-report.json
```

The input is a JSON array. `label` and `family` are optional; `family` should identify variants of
the same original source when measuring exact-metadata linkability.

```json
[
  {"id":"azoth-escrow-001","bytecode":"0x...","label":true,"family":"escrow-a"},
  {"id":"ethereum-negative-001","bytecode":"0x...","label":false,"family":"negative-001"}
]
```

The report includes per-sample features and scores, AUROC, tie-aware average precision, fixed
threshold confusion matrices, empirical TPR at several low-FPR ceilings, one-sided 95% Wilson
upper bounds for FPR, feature prevalence by class, repeated metadata suffix clusters, and
normalized source-family linkability. It warns when family variants are being treated as separate
samples or the negative corpus cannot support a low-FPR claim. Unlabelled corpora produce
descriptive results without classification claims.

To generate deterministic local Azoth positives from the checked-in escrow and counter fixtures:

`runtime` mode executes each transformed creation payload in REVM and records the materialized
deployed code that an on-chain observer would see, including constructor-written immutables. The
generator aborts instead of emitting a partial corpus if any requested fixture/seed fails or if a
selected artifact is byte-for-byte identical to its baseline. Exact identities are therefore never
mislabelled as positive examples. The final positional argument deterministically selects `all`
(the default), `escrow-erc20`, or `counter`; selecting `counter` is useful when a current safety
gate intentionally leaves the ERC20 fixture unchanged.

```bash
# 20 seeds per fixture; fails atomically if any selected output is unchanged
cargo run -p azoth-analysis --example generate_azoth_corpus -- 20 azoth-foundation-v4 runtime no-mask all

# Request only genuinely changed counter samples
cargo run -p azoth-analysis --example generate_azoth_corpus -- 20 azoth-foundation-v4 runtime no-mask counter

# Explicitly red-team the non-production constructor mask
cargo run -p azoth-analysis --example generate_azoth_corpus -- 20 mask creation mask counter
```
