# Azoth Transforms

`azoth-transform` applies deterministic, seed-derived rewrites to Azoth's CFG/IR. A pass runs against a cloned bundle and is committed only when it succeeds and reports a change; errors abort the pipeline and unsuccessful attempts cannot leave partial mutations behind. This transaction boundary is useful defensive behavior, but it is not a proof that a rewrite preserves every EVM observation.

## Production default

The unified obfuscator applies passes in this order:

1. `FunctionDispatcher`, only when a supported Solidity-style dispatcher is detected.
2. `JumpTrampoline`.
3. `ClusterShuffle`.

`FunctionDispatcher` replaces dispatcher selector literals with deterministic four-byte tokens and returns the original-selector-to-token mapping required by callers. The default selector-only mode does not add controller, decoy, or storage-dependent blocks. It rejects a selector that also appears outside the recognized dispatcher because Azoth cannot yet prove whether that occurrence participates in a self-call or interface data flow. Token collisions with every original selector are excluded.

`JumpTrampoline` reroutes a small seed-derived sample of existing symbolic jumps through ordinary forwarding blocks. It changes CFG topology without dead branches, storage reads, or environment-dependent predicates and adds at most three five-byte blocks.

`ClusterShuffle` moves maximal clusters connected only by explicit jumps. It anchors the entry cluster, keeps fallthrough/false-branch sequences adjacent, and searches seed-derived safe layouts until clean-runtime LCS retention is at most 40% when possible. It then recalculates program counters and runtime bounds.

Recognized Solidity IPFS or Swarm metadata digests are also diversified automatically after runtime encoding. The CBOR envelope and compiler version remain intact, but the derived digest is intentionally not a valid source-verification pointer.

Constructor-argument masking is automatic when the deployment payload contains a supported argument suffix. See [constructor-argument obfuscation](../../docs/constructor-argument-obfuscation.md) for its public-data security boundary.

## Experimental and legacy passes

The other exported passes are opt-in and are not part of the production default. They need contract-specific differential validation before use. In particular:

- The legacy multi-tier dispatcher is available only through constructors named `experimental_multi_tier`; it adds controller, decoy, and storage-dependent blocks and is excluded from normal orchestration.
- `StringObfuscate` is disabled and returns an error because scrambling `Error(string)` data changes observable revert bytes. Use `LiteralSynthesis` for exact constant rewrites.
- `LiteralSynthesis` exactly reconstructs selected constants but is not a default because red-team testing found its repeated algebraic templates were an easy family classifier.
- `ArithmeticChain`, `Shuffle`, `OpaquePredicate`, `JumpAddressTransformer`, `PushSplit`, `StorageGates`, `SlotShuffle`, and `Splice` remain available for explicit experiments; they are not safety-certified defaults.

## Unsupported runtime observations

Layout-changing orchestration currently rejects runtimes that use `PC`, `CODESIZE`, or `CODECOPY`, because Azoth does not yet have typed relocation records for embedded code/data references. It conservatively rejects every `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` use as well: without sound stack and address-alias analysis, their target may be the current contract and therefore expose transformed code size, bytes, or hash. Passes that add executed instructions, including `JumpTrampoline` and experimental `LiteralSynthesis`, also skip or reject every `GAS`-observing runtime; even the standard `GAS; CALL` sequence can expose added overhead through EIP-150 forwarding. Unsupported or ambiguous inputs fail closed rather than being transformed speculatively.

These checks do not replace semantic testing. Before deployment, compare original and transformed contracts in an EVM across successful calls, reverts and returndata, logs, storage, balances, and relevant environment inputs.

## Transform interface

```rust
pub trait Transform: Send + Sync {
    fn name(&self) -> &'static str;
    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool>;
}
```

Use `ObfuscationConfig::default()` or `ObfuscationConfig::with_seed(...)` for the production pass set. Supplying `config.transforms` explicitly replaces `JumpTrampoline` and `ClusterShuffle`; dispatcher detection still runs first. The full obfuscator should be preferred over invoking passes directly because it provides transactional application, domain-separated randomness, reindexing, relocation patches, size checks, and result metadata.
