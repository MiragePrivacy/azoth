# Constructor-argument obfuscation report

> **Historical experimental result — not a release recommendation.** This document records an
> earlier constructor-mask prototype and its local measurements. The current safe foundation
> profile disables constructor-argument masking. Subsequent local red-team evaluation recognized
> the decoder across the evaluated corpus, so the prototype failed Azoth's stealth gate. Its test
> counts and benchmark figures below describe that earlier experiment, not the current profile and
> not production evidence.

## Executive report

The experimental pass removed literal constructor-tail disclosure in its supported test shapes without changing the input Solidity, source bytecode, or ABI. The deployment runtime supplied to Azoth defined the boundary exactly; bytes after that complete runtime were masked, and seed-varied init code restored them in memory before the original constructor continued. In those experiments, the returned creation payload no longer contained the original ABI suffix verbatim. This bounded behavior was not a proof for arbitrary constructors or environments.

This was intended as a bounded Azoth-only response to `mirage-adversarial-privacy-report.md`. Constructor code and transaction input are public, so bytecode-only obfuscation cannot provide cryptographic confidentiality: a capable analyst can execute the init code or reverse its data flow, and any constructor value later written to public runtime code, storage, logs, calls, or proofs remains observable there. The prototype raised the report's zero-effort static ABI-tail recovery into a program-analysis problem for its supported shapes. It did not solve the report's public-state, proof-disclosure, or CBOR metadata-fingerprint findings.

The prototype did not intentionally emit an Azoth marker, version header, fixed key, or one fixed decoder byte string. The full runtime was used as an authoritative boundary, while decoder chunk order, arithmetic constants, instruction chains, and trampoline form were seed-derived. Those variations did not make the construction unrecognizable: the later local detector identified the common self-decoding structure across the evaluated samples. Absence of a literal marker is therefore not evidence of indistinguishability.

The prototype attempted to fail closed for the supported shapes: an absent or ambiguous runtime, an unsupported argument-copy site, an unsafe trampoline, or an EIP-170/EIP-3860 size violation returned an error. That parser and its differential tests were still narrower than complete EVM semantic equivalence.

## Technical report

### Root cause

The previous pipeline treated constructor data as untouched recovery material. Section detection also examined the end of the whole creation payload for Solidity CBOR metadata even though constructor arguments follow the compiler-generated creation bytecode. ABI words could therefore be mistaken for metadata, while the real argument suffix was reassembled unchanged. In the reported deployment this made all six recipient/token/amount rows recoverable by reading aligned words at the tail; no EVM analysis was necessary.

### Historical design and implementation

The experimental prototype had four cooperating parts:

1. **Exact section boundaries.** The complete caller-supplied runtime must occur exactly once in the deployment payload. Its start separates init from runtime, its own CBOR trailer is split as auxdata, and every byte after its end is classified as `ConstructorArgs`. This is byte-exact and works for static, dynamic, packed-looking, all-zero, and adversarial argument values without ABI guessing.

2. **Seed-derived masking.** The argument suffix is divided into 32-byte chunks and XOR-masked byte-for-byte. Masks are derived deterministically from the Azoth seed, a domain separator, and the argument length. Chunk order is shuffled, and each mask is synthesized with the existing arithmetic-chain vocabulary rather than stored as one direct key constant.

3. **Init-code decoding.** Azoth locates one exact Solidity-style `CODESIZE - creation_length` argument `CODECOPY`. It replaces bytes inside that basic block with a trampoline and appends a decoder to init code. The decoder performs the original copy, unmasks memory in seed-shuffled order, then replays the displaced original instructions. Existing init jump destinations do not move. Direct, PC-relative, XOR-split, and SUB-split trampoline forms are selected by seed and available space. PC-sensitive displaced blocks are rejected.

4. **Correct recovery.** Reassembly now distinguishes deployed suffixes such as CBOR auxdata from transaction-only constructor arguments. Runtime `CODECOPY`/`RETURN` lengths exclude the arguments, creation offsets account for decoder growth, and the constructor's original creation-length constant is patched. Immutable-reference offsets continue to be remapped after runtime transforms. The final payload is checked against the 24,576-byte EIP-170 runtime limit and 49,152-byte EIP-3860 initcode limit.

The library retains an explicit experimental opt-in through
`ObfuscationConfig::obfuscate_constructor_arguments`. It is **not** automatically applied by the
current safe profile, and the safe CLI does not expose it as an admitted pass. Result metadata still
records `constructor_args_obfuscated`, `constructor_argument_bytes`, and
`constructor_decoder_bytes` for research harnesses; those fields are not a release attestation.

### Historical test snapshot

The following table was captured during the earlier prototype work. It was useful regression
evidence for the tested fixtures, but it did not establish complete equivalence or stealth and must
not be combined with current-profile results.

| Check | Scope | Result |
|---|---:|---:|
| Core, transform, and CLI tests | 105 tests | Passed; 1 explicit benchmark ignored in normal runs |
| Focused randomized differential test | 64 argument/seed/length cases; 128 REVM deployments | Byte-for-byte identical deployed runtimes; includes a 704-byte report-sized suffix and partial final words |
| Full-pipeline immutable test | Runtime transforms plus constructor decoding | Decoded recipient and amount reached remapped immutable locations |
| Built-in parallel fuzz campaign | 1,000 successful cases | 0 errors, 0 deployment mismatches, 0 saved crashes; 12.4 s (81.3 iterations/s) |
| Plaintext oracle | Every escrow fuzz case | Complete 160-byte suffix and each nonzero address/amount ABI word absent from output |
| Determinism/diversity | Repeated and distinct seeds | Same seed reproduced output; different seed changed it |
| Static analysis | `cargo clippy ... -D warnings` | Passed |
| Formatting | `cargo fmt --all -- --check` | Passed |

The built-in campaign varied seeds, constructor recipients and amounts, and transform selections. Its REVM oracle required successful creation, while the focused test compared deployed runtime bytes for its selected cases. Neither check covered arbitrary calls, state transitions, logs, reverts, external effects, gas-sensitive behavior, forks, or all compiler shapes.

At the time of this snapshot, the full workspace build could not compile the external Z3-backed crate because `z3.h` was absent. More importantly, the current production-facing equivalence verifier intentionally returns `VerificationUnavailable`; compiling Z3 does not turn the incomplete encoding into proof evidence.

### Historical benchmark

Fixture: the repository's Solidity 0.8.30 ERC20 escrow with a 160-byte constructor suffix. These earlier measurements used a release build and REVM. Size/gas deltas compare the original creation payload with the experimental constructor-mask-only result for one representative deterministic seed; decoder distribution and transform time covered 100 deterministic seeds. They are retained for historical engineering context only.

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Creation payload | 9,129 B | 9,700 B | +571 B (+6.26%) |
| REVM deployment gas | 1,861,722 | 1,869,364 | +7,642 (+0.410%) |
| Intrinsic calldata gas | 139,224 | 146,608 | +7,384 (+5.30%) |
| Deployed runtime | baseline | byte-for-byte identical | 0 B |
| Verbatim 160-byte ABI suffix | present | absent | removed |

Across 100 seeds, decoder size averaged 569.7 bytes (433 minimum, 711 maximum), and masking averaged 124.1 microseconds per creation payload in the release benchmark. Cost grows approximately with the number of 32-byte chunks; these figures should not be extrapolated as measurements of the report's larger multi-row payload without benchmarking that exact fixture.

### Security boundary and current decision

In its supported experiments, the pass removed the direct verbatim-suffix extraction path. It did not encrypt transaction calldata, hide values after EVM decoding, suppress storage/log/call/proof disclosures, remove Solidity CBOR metadata, or prevent dynamic/symbolic recovery. The recognizable decoder also created an Azoth-specific classification signal.

**Decision: do not roll this pass into the safe profile.** Current safe-profile evaluation must leave
`obfuscate_constructor_arguments` disabled. Redesign requires a representative Ethereum negative
corpus, an out-of-sample detector gate, complete constructor semantic obligations, and differential
behavior coverage before reconsideration. Teams that require constructor-value confidentiality
from validators, archive nodes, or skilled reverse engineers need a cryptographic protocol change;
public self-decoding init code cannot provide that confidentiality.
