# Azoth obfuscation hardening technical report

Date: 2026-08-18  
Baseline: `6634a2707c82` (`feat: mask constructor arguments during obfuscation (#150)`)  
Scope: Solidity 0.8.30-style legacy EVM deployment/runtime bytecode

## Result

The production pipeline is substantially stronger and safer, but the result needs a precise qualification.

On the 509-byte Counter deployment used for the before/after study, 100 deterministic seeds produced a **minimum 56.7780% conservative byte change** and a mean of 58.9568%. The previous pipeline changed 3.97% by the same rounded baseline measure. The minimum improvement is therefore **14.30x**, and all 100 deployment bytecodes, runtimes, opcode skeletons, selector sets, and metadata digests were unique. Output size was 514 bytes, or 1.0098x the input.

This establishes the requested 10x and 50% thresholds for that benchmark, not for every supported contract. A small runtime with a `GAS` observation, for example, can safely receive only selector replacement and changed about 11% in a regression fixture. Azoth must therefore measure and reject weak artifacts rather than advertise a universal 50% guarantee.

The most important outcome is the new fail-closed foundation. Several pre-existing paths could silently change semantics, report unsupported verification as success, or consume excessive CPU on adversarial CFGs. Those paths are now rejected, bounded, or covered by differential tests.

## Threat model and anonymity-set evidence

Azoth assumes the observer can obtain creation input, deployed code, calldata, receipts, traces, state, and historical chain data. Obfuscation can raise static and dynamic analysis cost; it cannot make public EVM data confidential. Constructor masking in particular removes a plaintext ABI tail but remains reversible by executing or analyzing init code.

The intended product direction matches Mirage's stated focus on making deployments harder to link while preserving behavior: [Azoth introduction](https://docs.mirageprivacy.com/azoth/introduction/), [technical model](https://docs.mirageprivacy.com/understanding-mirage/technical-model/), and [undetectability challenge](https://docs.mirageprivacy.com/understanding-mirage/the-undetectability-challenge/). Those documents describe a goal; they are not evidence that the current implementation is indistinguishable.

Blink's public SQL interface was usable for a first-order anonymity-set sample. The following queries were run on 2026-08-18 through [Blink](https://blink.mirageprivacy.com/) and its [SQL documentation](https://blink.mirageprivacy.com/docs.html#sql):

```sql
SELECT COUNT(*) AS total_contracts,
       SUM(CASE WHEN is_verified THEN 1 ELSE 0 END) AS verified_contracts,
       SUM(CASE WHEN NOT is_verified THEN 1 ELSE 0 END) AS unverified_contracts,
       ROUND(100.0 * AVG(CASE WHEN is_verified THEN 1 ELSE 0 END), 2) AS verified_pct
FROM contract_metadata;
```

Result: 104,876,220 contracts, 7,445,598 verified, 97,430,622 unverified, and 7.10% verified.

```sql
SELECT COUNT(*) AS unverified_solc_0830,
       ROUND(AVG(n_code_bytes), 1) AS mean_bytes,
       quantile_cont(n_code_bytes, 0.5) AS median_bytes,
       quantile_cont(n_code_bytes, 0.95) AS p95_bytes,
       ROUND(100.0 * AVG(CASE WHEN uses_push0 THEN 1 ELSE 0 END), 2) AS push0_pct,
       ROUND(100.0 * AVG(CASE WHEN has_source_hash THEN 1 ELSE 0 END), 2) AS metadata_pct
FROM contract_metadata
WHERE NOT is_verified
  AND compiler_version = '0.8.30'
  AND n_code_bytes > 0;
```

Result: 42,785 contracts; mean 2,644.7 bytes; median 438 bytes; p95 8,043 bytes; 87.83% use `PUSH0`; 96.02% have source-hash metadata.

This is useful calibration, not an indistinguishability result. The query does not measure opcode motifs, normalized CFGs, metadata resolution, source family, optimizer settings, proxy patterns, deployment factories, or classifier performance. A representative corpus must be sampled and analyzed before claiming the 97.4-million-contract set as Azoth's effective anonymity set.

## Production transformation portfolio

The unified obfuscator now applies the following deterministic, seed-derived operations.

### Selector-only function dispatcher

For a recognized Solidity dispatcher, each four-byte selector literal is replaced with a unique seed-derived four-byte token. Azoth returns an original-selector-to-token map so callers can rebuild calldata. Tokens cannot collide with one another or with any original selector. Ambiguous duplicate selectors and selector literals found outside the recognized dispatcher fail closed because they could participate in self-calls or other interface data flows.

The production mode does not add controllers, storage gates, decoy branches, or environment-dependent behavior. The former multi-tier design remains explicit experimental code.

Only the first four calldata bytes are changed. ABI argument offsets, widths, and encodings are not yet diversified.

### Jump trampoline

This new pass reroutes a seed-derived sample of existing symbolic jump edges through one to three ordinary `JUMPDEST; PUSH2; JUMP` forwarding blocks. It introduces genuine CFG nodes and edges without opaque predicates, storage reads, or dead branches. A `STOP` barrier preserves the EVM's implicit end-of-code behavior when appending nodes would otherwise make a former fallthrough execute new code. Runtimes that fall into an existing deployed suffix are skipped.

### Cluster shuffle

Cluster shuffling was redesigned around semantic layout constraints and an exact LCS objective. It groups blocks connected by mandatory physical fallthrough, anchors the runtime entry, preserves `JUMPI` false-path adjacency and end-of-code behavior, then searches a bounded set of seed-derived layouts. When possible, it accepts a layout whose clean-runtime byte LCS retention is at most 40%.

The exact LCS implementation is bit-parallel rather than quadratic, and candidate trials shrink near the EIP-170 limit. A 23,996-byte synthetic runtime with 4,798 forwarding blocks completed all ten tested transformations in a mean 76.4 ms (p95 77.3 ms, maximum 77.3 ms).

### Compiler metadata digest diversification

Recognized Solidity IPFS or Swarm digests are changed deterministically while retaining the CBOR envelope and compiler-version fields. This avoids a constant original source digest across variants and matches the high observed prevalence of metadata in the sampled Solidity 0.8.30 population.

The generated digest intentionally does not resolve to source content. Active source-resolution failure can itself be a classifier feature, so this is an interim measure rather than a solved fingerprint problem. Metadata is not rewritten when self-code-sensitive behavior makes byte changes unsafe.

### Constructor-argument masking and init-code relocation

When an exact constructor-argument suffix is detected, Azoth masks it and inserts a deterministic decoder so the deployed runtime is unchanged without retaining a plaintext ABI-aligned tail. The output reports whether masking occurred and the argument/decoder byte counts.

Init-code patching now requires symbolic evidence. A relocatable Solidity immutable write must derive its destination from the exact base retained from the deployment `CODECOPY`, and `RETURN` must reuse that same base and length. Each moved runtime placeholder must be patched exactly once. Coincidental arithmetic literals that happen to equal a runtime PC are rejected rather than rewritten.

## Safety and correctness findings

| Finding | Risk before this work | Resolution |
|---|---|---|
| Equivalence API returned proof-shaped success without a complete EVM model | False assurance about arbitrary contracts | `prove_equivalence` now returns `Unsupported`; empty/vacuous proofs, malformed formulas, solver `unknown`, and unsupported syntax fail closed. Z3 remains optional scaffolding. |
| String pass scrambled `Error(string)` bytes | Observable revert-data semantics changed | Production string transformation is disabled and returns an error. |
| Passes could mutate the shared IR before reporting failure/no-change | Partial corruption could leak into later passes | Every pass runs on a clone and commits transactionally only after success and a reported change. |
| One sequential RNG coupled unrelated passes | Adding/skipping a pass changed all later choices | Each pass receives a domain-separated RNG derived from the root seed and pass identity. |
| Hash-map iteration affected mapping order | Same seed could vary across processes/platforms | Inputs are sorted before seeded decisions; determinism regressions cover mappings and output. |
| Dispatcher tokens could collide with original selectors or ambiguous duplicates | Wrong function dispatch or aliasing | Reserve all original selectors, require unique tokens, reject ambiguous occurrences, and return the complete mapping. |
| Numeric literals equal to a `JUMPDEST` PC were treated as jump addresses | Storage/data/constants could be silently relocated | Runtime-wide abstract stack provenance now proves which PUSH origins reach jump targets; mixed address/data use fails closed. `PUSH0` targets are tracked explicitly. |
| Exact-path provenance could grow exponentially | Adversarial bytecode caused approximately 19 seconds of analysis for a 1,529-byte fixture | Compatible states are joined, pending keys are deduplicated, and path-state, stack-cell, fact-growth, transfer-work, and iteration budgets fail closed. The same adversary now aborts in about 1.43 seconds in a debug build while the large real escrow fixture completes. |
| Init reassembly patched PUSH values based on numeric coincidence | An unrelated `ADD; MSTORE` sequence could corrupt the deployed runtime | Relocation requires an exact symbolic `CODECOPY` base/length proof and exact placeholder coverage. A minimized corruption reproducer is now a fail-closed regression. |
| Cluster movement broke fallthrough and unresolved `JUMPI` false edges | Different control flow or execution into the wrong block | Mandatory physical adjacency is modeled as a cluster constraint; unresolved dynamic jumps fail closed. |
| Appended trampolines changed implicit EOF `STOP` behavior | Formerly terminating code could execute the trampoline region | Add a barrier where safe; skip runtimes that fall through into a deployed suffix. |
| Layout changes ignored `PC`, `CODESIZE`, `CODECOPY`, and self-targeting `EXTCODE*` observations | A contract could observe changed offsets, bytes, length, or hash | Production layout changes reject these patterns. All `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` are conservatively rejected until address-alias analysis exists. |
| Added executed instructions changed `GAS` observations and EIP-150 forwarding | Calls or branches could change despite identical logical code | Overhead-adding passes skip/reject every runtime containing `GAS`. |
| Decoder placeholders could turn unknown bytes into `INVALID` on encode | Future or unsupported opcodes could be corrupted | Original raw opcode bytes are preserved exactly when possible; unsafe recovery fails closed. |
| Runtime/init sizes and gas fields were incomplete or misleading | Invalid artifacts or fabricated cost estimates | Enforce 24,576-byte runtime and 49,152-byte initcode limits. Report exact runtime code-deposit gas only; runtime execution and full creation gas require measurement. |
| Analysis used weak/unstable metrics and incorrect post-dominator/size inputs | Scores could improve without real diversification | Added exact LCS, longest contiguous match, aligned difference, pairwise output metrics, n-gram Jaccard, current encoded size, and corrected exit-root post-dominators. |

These guards intentionally reduce coverage. A rejected contract is safer than a transformed contract whose semantics depend on unmodeled code layout, gas, or dynamic control flow.

## Obfuscation and fingerprint benchmark

### Method

The benchmark uses the checked-in Solidity Counter creation bytecode across seeds 0 through 99. Its original artifact is 509 bytes: 28 bytes of init code, 428 bytes of clean runtime, and 53 bytes of compiler metadata, containing 267 decoded runtime opcodes. Each output used the production default and was compared both to the original and to every other seed.

The primary conservative change measure is:

```text
1 - LCS(original deployment bytes, output deployment bytes) / original deployment bytes
```

Unlike position-by-position difference, insertions do not make every following byte look changed. Longest common contiguous retention measures the largest surviving source slice. Opcode-LCS removes immediate-byte noise. Pairwise measures test whether different seeds create meaningfully different variants rather than merely changing a seed tag.

### Results over 100 seeds

| Measure | Minimum | Mean | Median | p95 | Maximum |
|---|---:|---:|---:|---:|---:|
| Conservative changed bytes | 56.7780% | 58.9568% | 58.9391% | 60.1277% | 60.7073% |
| Aligned byte difference | 85.6031% | 88.5311% | 88.6187% | 90.0875% | 90.6615% |
| Longest original contiguous run retained | 9.0373% | 9.2927% | 9.2338% | 9.6267% | 10.6090% |
| Pairwise aligned difference | 63.4241% | 82.1214% | 83.0739% | 85.4086% | 87.1595% |
| Original-to-output opcode-LCS retention | 46.8165% | 50.5506% | 50.5618% | 52.8090% | 53.9326% |
| Pairwise opcode-LCS retention | 46.6667% | 57.1000% | 57.0370% | 62.9630% | 70.0000% |

Additional results:

- Worst conservative seed: 50, with an LCS of 220/509 bytes.
- Old rounded baseline: 3.97% conservative change and approximately 27.8% size growth.
- Improvement over that baseline: minimum 14.3018x and mean 14.8506x.
- Output size: 514 bytes, 1.009823x the original.
- Uniqueness: 100/100 deployment bytecodes, runtimes, opcode skeletons, and metadata digests; 300/300 selector tokens.
- Source-matched generation latency: mean 13.1 ms and p95 18.4 ms.
- Reproducibility: the concatenated 100-seed corpus SHA-256 is `7405f44b3f1607645932ed8aff07c780794649d14fae9c6aaef921c4d8133472`; seed 0 is `30c8603df21db7a816e0dbf33e0382539af5d1d22f83eaafb76f91d1b124b3cd`, and worst seed 50 is `f3b83bcde4e0b097c47570e4823f8a72075e40e514576d6ba32440ed93a2f317`.

The conservative measure is the release criterion. The aligned measure is diagnostic because layout insertion can inflate it. Opcode retention and longest-run retention expose variants that change immediates while leaving most structure untouched.

### Red-team conclusions

The output family is harder to link by exact bytes, selectors, metadata, and raw block order. It does not yet defeat expert normalization.

- The 100 outputs had 14 raw CFG shapes. Contracting simple forwarding nodes reduced every output and the original to one normalized CFG shape. Jump trampolines therefore add analyst work but not durable structural ambiguity against a normalizer.
- Experimental `LiteralSynthesis` was detected in 100/100 transformed samples and 0/4 native compiler controls using a simple algebraic-template heuristic. It created 3-11 recognizable patterns per sample (mean 7.08), covering about 9.34% of opcodes and 22.45% of bytes. It was rejected from the default portfolio.
- A non-resolving metadata digest is structurally compiler-like but can be detected by an active resolver.
- Selector replacement changes the public interface and may be visible in transaction-flow analysis even though the tokens themselves are not a fixed Azoth signature.
- Low-density forwarding blocks resemble shapes used by Solidity/Yul, but a classifier trained on local motifs and their placement still needs to be measured.
- No classifier AUC or low-false-positive-rate result exists yet. Consequently, the effective anonymity set is unknown and should not be equated with all unverified contracts.

The honest assessment is that Azoth now defeats much more shallow static matching and raises the cost of manual recovery, but an AI-assisted expert can still normalize away its principal CFG addition and follow the returned selector interface through observed transactions.

## Validation performed

Final source gates:

```text
cargo fmt --all -- --check
    passed

Z3_SYS_Z3_HEADER=/opt/homebrew/include/z3.h \
LIBRARY_PATH=/opt/homebrew/lib \
cargo clippy --workspace --all-targets --all-features -- -D warnings
    passed

cargo test --workspace --all-targets
    248 passed; 0 failed; 9 ignored

Z3_SYS_Z3_HEADER=/opt/homebrew/include/z3.h \
LIBRARY_PATH=/opt/homebrew/lib \
cargo test -p azoth-verification --features z3
    18 passed; 0 failed

cargo run -q -p azoth-cli -- fuzz -j4 -i200 \
    --check-deploy --crash-dir /tmp/azoth-fuzz-final2
    204 iterations; 200 successes; 0 errors;
    0 deployment mismatches; 0 saved crashes
```

The fuzz harness exercises escrow and Counter fixtures with no transform, jump trampolines, and cluster shuffling, then deploys the outputs in REVM. The dedicated Counter differential test runs three fixed seeds through deployment and 16 logical calls, comparing success/revert class, exact return/revert bytes, logs, account/storage state, balances, nonpayable behavior, malformed/unknown calldata, and overflow behavior. It also checks repeat determinism, selector uniqueness, and EVM/relative size ceilings.

Additional regressions cover real constructor-initialized runtime/immutable data, ERC-20 proof collection, unresolved jumps, false fallthrough, EOF, init/runtime literal-PC collisions, unknown opcodes, self-code inspection, `GAS`, transactional failures, and near-limit candidate-search bounds.

Passing this corpus is evidence for the covered contracts and states, not a proof for arbitrary EVM programs.

The final independent safety audit found no P0/P1 blocker in the documented Solidity 0.8.30/default path. The bounded 1,529-byte provenance adversary still takes about 1.4 seconds in a debug build before failing closed, so an outer service CPU/time limit remains an operational P2 requirement.

## Release metrics and proposed gates

Metrics must be computed on creation bytes, clean runtime, decoded opcode stream, normalized CFG, execution transcripts, and a representative chain corpus. One aggregate potency score is not sufficient.

| Dimension | Metric | Initial release gate |
|---|---|---|
| Semantics | Differential agreement over deployment, returndata/revertdata, logs, storage, balances, selfdestruct/calls, and relevant environments | 100% for every artifact in its contract-specific corpus; otherwise reject |
| Determinism | Exact deployment/runtime/mapping equality across repeat runs, processes, and supported platforms | 100% |
| Original retention | `1 - byte_LCS/original_len` on the complete deployment | At least 50% for an artifact marketed at the requested strength; otherwise reject or label weak |
| Surviving chunks | Longest common contiguous original slice | At most 12% of input and at most 64 bytes, with an explicit exception policy for very small inputs |
| Structural retention | Opcode LCS and normalized CFG graph-edit/similarity | Track per size/source stratum; reject unexplained regressions |
| Seed diversity | Pairwise byte/opcode LCS, aligned difference, n-gram Jaccard, uniqueness | 100% exact uniqueness; median pairwise aligned difference at least 30% |
| Size | Runtime/init growth distributions plus protocol limits | p95 at most 1.25x, maximum at most 1.50x, and always below EIP-170/EIP-3860 limits |
| Gas | Measured deploy and runtime gas distributions for workloads | p95 at most 1.25x and maximum at most 1.50x; never infer runtime gas from byte size |
| Detectability | Cross-validated classifier on held-out source families and compiler settings | ROC-AUC at most 0.60 and true-positive rate at most 5% at 0.1% false-positive rate |
| Metadata | Envelope distribution, compiler fields, and active digest resolution | Match the target corpus; do not ship one universal resolution-failure pattern |
| Robustness | Fuzz/differential failures, timeouts, crashes, nondeterminism | Zero; all analysis budgets fail closed |

The classifier gate is the closest operational measure of the desired anonymity set. Evaluation must split by source/project family so near-duplicate contracts cannot leak across train and test sets. Results should also be stratified by code size, compiler version, optimizer settings, proxy/factory family, and `PUSH0`/metadata presence.

## Attempts, decisions, and rejected directions

| Attempt | Result | Decision |
|---|---|---|
| Legacy random block shuffling | Low conservative change, large growth, and unsafe physical-fallthrough assumptions | Replaced by cluster-constrained, LCS-scored layouts |
| Multi-tier dispatcher/controller/decoy design | More visible synthetic machinery and greater semantic surface | Keep explicit experimental only; production uses selector literals only |
| String scrambling | Changed observable revert data | Disable |
| Literal algebraic synthesis | Exact in isolation but trivially classified in 100/100 samples | Keep opt-in experimental; redesign with compiler-corpus-derived, heterogeneous lowering before reconsideration |
| Metadata digest replacement | Removes cross-seed digest equality but creates non-resolution risk | Keep as an interim diversified field and add active-resolution corpus testing |
| Exact path-sensitive jump provenance | Sounder-looking but exponential on ordinary internal-call fan-in | Use conservative joined states with explicit work budgets |
| Numeric immutable/PC heuristics | Fast but produced concrete semantic corruption reproducers | Replace with symbolic provenance and fail closed when proof is incomplete |
| Formal-equivalence claim on partial SMT scaffolding | Unsound product claim | Return `Unsupported` until a complete relational EVM model exists |

## Remaining limitations and next work

1. Build a ≥50-contract Solidity 0.8.30 differential corpus spanning escrow, ERC-20/721, proxies, factories, access control, custom errors, immutables, external calls, CREATE/CREATE2, logs, and adversarial fallback/receive paths. Run hundreds of seeds per stratum.
2. Make the ≥50% conservative-change threshold an opt-in/output policy enforced by the CLI and API. Small, `GAS`-observing, or weakly transformable contracts must be rejected rather than silently accepted at low potency.
3. Add transformations that survive forwarding-node contraction: compiler-corpus-derived equivalent dispatcher trees, safe basic-block splitting/merging, and typed data/code relocation. Each needs differential and gas proofs for its supported subset.
4. Diversify full calldata argument encoding only behind generated client adapters and explicit mappings. Current Azoth changes selectors only.
5. Train the low-FPR family classifier against Blink-derived samples and publish confidence intervals, feature ablations, and source-family-held-out results.
6. Replace non-resolving metadata digests with a policy that matches the selected anonymity stratum, or allow an explicitly measured metadata-free stratum.
7. Extend code-layout and address-alias analysis so safe `PC`/`CODECOPY`/self-`EXTCODE*` cases can be relocated rather than categorically rejected.
8. Measure runtime gas with stateful workloads. The current report correctly limits itself to exact byte counts and code-deposit gas.
9. Treat formal equivalence as future work. A sound implementation needs full 256-bit EVM semantics, calls, reverts, logs, storage, balances, gas, environmental inputs, intentional selector mappings, and counterexample-oriented proof obligations.

Until those gates exist, generated contracts should remain experimental and contract-specific differential validation is mandatory.
