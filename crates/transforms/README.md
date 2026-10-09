# Azoth transforms

This crate contains Azoth's bytecode passes and the fail-closed orchestration pipeline. A pass
implements the synchronous `Transform` trait and edits `CfgIrBundle`, the relationship-aware EVM
control-flow representation from `azoth-core`.

## Safe default profile

The default and `ObfuscationConfig::with_seed` profiles admit `ClusterShuffle`. The CLI rejects
the legacy pass names listed below. A library caller can still instantiate them for research, but
that is not a production endorsement. “Safe” here means conservatively admitted by the current
checks; it does not mean formally proven or production-ready.

`ClusterShuffle` permutes complete block clusters. A cluster is the smallest ordered set that must
stay together because of fallthrough, branch-false adjacency, section boundaries, or PC-relative
control. The pass keeps the runtime entry and end-of-code fallthrough anchors fixed and refuses to
run when control targets are unresolved or the code observes its own layout/bytes/hash. Static
jumps and stack-proven Solidity return addresses are represented as stable block relationships;
numeric PCs are written only during final lowering.

An experimental opt-in can relabel selectors inside a detected native Solidity dispatcher without
changing its opcode shape. The returned private interaction manifest maps original selectors to
the replacement four-byte values. It is disabled in the safe profile: adapted calldata
changes `msg.sig`/`msg.data`, and the current literal guard cannot prove safety for forwarding,
hashing, proxies, self-calls, or dynamically synthesized selectors.

Every byte classified as compiler auxdata or padding is preserved byte-for-byte. Auxdata must be
a complete compiler CBOR map whose claimed start is also an EVM instruction boundary; a two-byte
length alone cannot split code or a PUSH immediate. This detector is still a parsing aid, not a
proof that a suffix is unreachable code. The safe pipeline therefore never rewrites an IPFS
or Swarm digest in place. Exact metadata remains a cross-variant linkage signal until a future
pass can prove that changing it preserves all code-observation and execution behavior.

When such a suffix exists, a layout change is allowed only if the retained runtime ends exactly
at a decoded terminal instruction and its control relationships are fully resolved. Otherwise the
suffix might be fallthrough code or a jump target that the CFG did not analyze, so the pipeline
fails closed. A no-op run may still return the byte-for-byte original artifact.

## Transaction and replay rules

Each pass receives a full 256-bit, input-bound, domain-separated RNG stream. Adding an unrelated
pass does not consume another pass's randomness. The same deployment bytes, runtime artifact,
seed, profile, and ordered pass list produce the same result.

Pass execution is transactional:

1. Clone the current IR.
2. Apply one pass to the clone.
3. Rebuild and validate relationships.
4. Commit the clone atomically only when the pass reports a change and validation succeeds.

A pass error aborts the pipeline. It is never converted into success, and partial mutations are
never returned. Finalization validates jump targets, patches supported immutable offsets, enforces
EIP-170/EIP-3860 limits, and fails closed when it cannot preserve a required relationship.
The safe pipeline also rejects any executable-runtime opcode whose stack and control
semantics are not modelled. Copying an unknown byte verbatim would not make moving its containing
block safe; ordinary `0xfe` (`INVALID`) remains supported as a known terminal instruction.

`ObfuscationResult` includes an input-bound seed commitment, Keccak hashes of input/output
artifacts, the ordered requested transform recipes and feature flags, and an HMAC-SHA3-256
reproduction tag. A recipe records each transform's name and canonical `configuration_id`, even
when the pass became a no-op. `verify_integrity` checks those fields using the private seed. The
standalone `PrivateInteractionManifest::verify_integrity` additionally authenticates a serialized
selector map and its exact calldata rule against separately supplied input/output artifacts. These
checks authenticate replay artifacts; they are not a proof of EVM equivalence. The CLI emits
selector mappings only through explicitly requested private outputs: the interaction manifest or
a CFG debug trace. Both are published without overwrite from a fully synced private temporary file;
neither must be published or embedded on-chain.

## Experimental and disabled passes

The following implementations remain available for tests and research but are rejected by the
safe CLI until they satisfy semantic, detector, and corpus gates:

- `Shuffle`: reorders individual blocks without the complete relationship policy.
- `OpaquePredicate`, `StorageGates`, and `Splice`: add recognizable synthetic control-flow motifs.
- `JumpAddressTransformer`, `ArithmeticChain`, and `PushSplit`: add normalizable arithmetic motifs
  and need stronger whole-program data-flow proofs.
- `SlotShuffle`: cannot yet prove arbitrary/dynamic storage addressing is completely remapped.
- `StringObfuscate`: changes observable revert/return payloads.
- constructor-argument masking: opt-in through
  `ObfuscationConfig::obfuscate_constructor_arguments`; it supports only some init-code shapes and
  its decoder was perfectly detected in the local red-team corpus.

The formal verifier is also fail-closed and currently reports verification unavailable. Release
decisions must therefore rely on explicit behavioral tests while the semantic model is completed;
checksums and successful deployment are not substitutes for equivalence proof.

## Adding a pass

A new pass should edit stable block identities and symbolic relationships, not concrete PCs. It
must have deterministic tests, transaction rollback/error tests, relationship validation, exact
replay coverage, REVM behavioral tests for success/revert/return/log/storage/calls, protocol-limit
tests, and a detector evaluation against compiler- and size-matched negative bytecode. It is added
to the CLI allowlist only after those gates pass.
