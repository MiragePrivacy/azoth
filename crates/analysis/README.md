# Azoth Analysis

The `azoth-analysis` crate provides analytical metrics for evaluating EVM bytecode obfuscation transforms. It measures structure, size, original-byte retention, and seed-to-seed diversity; it does not measure execution gas or prove semantic equivalence.

## Architecture

The analysis crate focuses on quantifying bytecode complexity through:

1. **Control Flow Complexity** - Basic block and edge counts in the CFG
2. **Stack Usage** - Maximum stack height measurements  
3. **Dominator Analysis** - Control flow critical points using dominator/post-dominator overlap
4. **Size Metrics** - Bytecode length tracking
5. **Obfuscation Persistence** - Conservative ordered-byte retention, longest contiguous runs, aligned differences, and pairwise n-gram similarity across randomized obfuscations

## Key Components

### Metrics System (`metrics.rs`)

Implements core metrics for evaluating bytecode complexity and transformation effectiveness:

- **Bytecode Size** (`byte_len`) - Encoded size of the current runtime CFG plus appended transform data
- **Block Count** (`block_cnt`) - Number of basic blocks in the CFG (excluding Entry/Exit)
- **Edge Count** (`edge_cnt`) - Number of edges in the CFG
- **Maximum Stack Peak** (`max_stack_peak`) - Maximum stack height across all body blocks
- **Dominator Overlap** (`dom_overlap`) - Fraction of nodes that are both dominators and post-dominators
- **Potency Score** (`potency`) - Composite score combining complexity metrics with overlap penalty

### Core Functions

The crate provides these primary functions:

- `collect_metrics(ir: &CfgIrBundle) -> Result<Metrics, Error>` - Collects metrics from the current CFG, including its current transformed byte length
- `current_byte_len(ir: &CfgIrBundle) -> usize` - Measures the instruction stream and appended transform data directly
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

Runs multiple obfuscation attempts with randomized seeds and aggregates:

- Longest common preserved byte sequences per iteration  
- Summary statistics (average, median, percentiles, range, standard deviation)  
- Histogram distribution of preserved lengths  
- Top ten most frequent preserved sequences  
- Conservative longest-common-subsequence retention and aligned original-to-output difference
- Pairwise aligned seed difference and pairwise n-gram set Jaccard similarity (n = 2, 4, 8)

Pairwise n-gram Jaccard replaces the former pooled unique-window percentage, whose value decreased mechanically as more iterations were added. The report stores ratios in `0.0..=1.0` and renders them as percentages.

Use `AnalysisConfig` to configure iterations, transform passes, and output path, then call `analyze_obfuscation(config)` to produce a markdown report. The CLI subcommand `azoth analyze` builds on this module.
