# Azoth Analysis

The `azoth-analysis` crate provides analytical metrics for evaluating EVM bytecode obfuscation transforms. This crate implements a minimal set of metrics to assess transform potency and gas efficiency.

## Architecture

The analysis crate focuses on quantifying bytecode complexity through:

1. **Control Flow Complexity** - Basic block and edge counts in the CFG
2. **Stack Usage** - Maximum stack height measurements  
3. **Dominator Analysis** - Control flow critical points using dominator/post-dominator overlap
4. **Size Metrics** - Bytecode length tracking
5. **Obfuscation Persistence** - Longest preserved byte sequences and n-gram diversity across randomized obfuscations

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

Runs multiple obfuscation attempts with randomized seeds and aggregates:

- Longest common preserved byte sequences per iteration  
- Summary statistics (average, median, percentiles, range, standard deviation)  
- Histogram distribution of preserved lengths  
- Top ten most frequent preserved sequences  
- N-gram diversity (n = 2, 4, 8) across obfuscated outputs

Use `AnalysisConfig` to configure iterations, transform passes, and output path, then call `analyze_obfuscation(config)` to produce a markdown report. The CLI subcommand `azoth analyze` builds on this module.
