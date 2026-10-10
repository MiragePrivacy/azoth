# Azoth obfuscation hardening executive report

Date: 2026-08-18  
Baseline: `6634a2707c82`

## Bottom line

Azoth's production pipeline is materially stronger and safer. On the 100-seed Counter benchmark, it changed at least **56.78%** of deployment bytes by a conservative LCS measure, versus **3.97%** before: a minimum **14.30x improvement**. All 100 outputs had unique deployment bytecode, runtime, opcode skeleton, selectors, and compiler-metadata digest, while output size grew only from 509 to 514 bytes (1.0098x).

That result satisfies the requested 10x/50% target for the benchmark, not universally. Small contracts and contracts whose semantics expose gas or code layout may transform less or be rejected. The product should enforce a per-artifact strength gate instead of making a blanket claim.

## What changed

- Added low-density jump trampolines that create real forwarding nodes and CFG edges.
- Rebuilt block shuffling to preserve fallthrough semantics and search for layouts with low original-byte retention.
- Hardened selector replacement, kept it compiler-shaped, and returned an unambiguous caller mapping.
- Diversified recognized compiler metadata digests without changing their CBOR/compiler envelope.
- Kept automatic constructor-argument masking and made init/immutable relocation require symbolic evidence.
- Made passes transactional and randomness domain-separated, improving failure safety and repeat determinism.
- Added exact byte/opcode retention, contiguous-run, pairwise diversity, and corrected CFG/size metrics.

## Critical safety work

The audit found and fixed or disabled several high-risk paths: false formal-verification success, observable revert-string mutation, selector collisions, runtime and init literals mistaken for jump/immutable addresses, broken fallthrough/end-of-code layouts, unsafe unknown-opcode encoding, self-code and gas observations, partial pass mutations, misleading gas/size reporting, and exponential CFG-provenance analysis.

Unsupported or ambiguous contracts now fail closed. Formal equivalence is explicitly `Unsupported`; it is no longer represented as a proof. Safety is established for tested contracts through differential execution, not a mathematical guarantee.

## Validation

- 248 workspace tests passed; 9 optional/benchmark tests were ignored; none failed.
- 18/18 tests passed with the optional Z3 feature.
- All-feature Clippy and formatting checks passed.
- Fuzzing requested 200 successes and completed 204 concurrent iterations with 200 successes, zero errors, zero deployment mismatches, and zero saved crashes.
- Dedicated differential tests compare deployment, calls, successes/reverts, exact output, logs, storage, balances, malformed calldata, nonpayable behavior, and overflow behavior.

## Red-team assessment

Shallow exact matching is much weaker: bytes, selectors, metadata digests, opcode layouts, and raw CFGs vary by seed. Expert normalization remains a real weakness. The 100 outputs had 14 raw CFG shapes, but contracting simple forwarding nodes reduced all of them to the original normalized shape. Experimental literal synthesis was trivially detected in 100/100 samples and was therefore excluded from the default pipeline. Non-resolving metadata can also be tested actively.

Blink reported 97,430,622 unverified contracts out of 104,876,220 on 2026-08-18, and 42,785 unverified Solidity 0.8.30 contracts in the sampled metadata table. That is a useful candidate corpus, not proof that all those contracts belong to Azoth's effective anonymity set. See [Blink](https://blink.mirageprivacy.com/) and its [SQL interface](https://blink.mirageprivacy.com/docs.html#sql).

## Recommendation

Proceed with Azoth as an experimental, fail-closed obfuscation pipeline and add a release gate requiring:

- 100% contract-specific differential agreement and repeat determinism;
- at least 50% conservative deployment-byte change for artifacts sold at this strength;
- bounded size and measured gas overhead;
- low longest-contiguous-source retention and strong seed-to-seed diversity; and
- held-out classifier performance near chance at operationally low false-positive rates.

The next priority is not more obvious algebraic noise. It is transformations that survive CFG normalization, a representative Solidity 0.8.30 corpus, full generated calldata adapters beyond selector replacement, active metadata-resolution testing, and a low-false-positive classifier benchmark.

Full details, findings, benchmark definitions, release metrics, and limitations are in [the technical report](AZOTH_TECHNICAL_REPORT.md).
