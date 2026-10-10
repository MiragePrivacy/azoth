# Constructor-argument obfuscation report

## Executive report

Azoth now removes the report's literal constructor-tail disclosure without changing the input Solidity, source bytecode, ABI, or deployed contract behavior. The deployment runtime supplied to Azoth defines the boundary exactly; all bytes after that complete runtime are masked, and seed-varied init code restores them in memory before the original constructor continues. The returned creation payload therefore no longer contains the original ABI suffix verbatim.

This is the strongest honest Azoth-only response to `mirage-adversarial-privacy-report.md`. Constructor code and transaction input are public, so bytecode-only obfuscation cannot provide cryptographic confidentiality: a capable analyst can execute the init code or reverse its data flow, and any constructor value later written to public runtime code, storage, logs, calls, or proofs remains observable there. The change specifically raises the report's zero-effort static ABI-tail recovery into a program-analysis problem. It does not claim to solve the report's public-state or proof-disclosure findings, and it does not alter the report's CBOR metadata fingerprint finding.

The implementation introduces no ABI-shaped heuristic and emits no Azoth marker, version header, fixed key, or fixed decoder byte string. The full runtime is already a required Azoth input and is used as an authoritative boundary. Decoder chunk order, arithmetic constants, instruction chains, and trampoline form are seed-derived. As with any public program transformation, a semantic classifier may still recognize self-decoding behavior; no non-ZK construction can honestly guarantee otherwise.

Safety is fail-closed. If the supplied runtime is absent or ambiguous, if the constructor has no single supported argument-copy site, if the trampoline cannot preserve existing init-code program counters, or if the result exceeds EIP-170/EIP-3860 limits, obfuscation returns an error instead of exposing plaintext arguments or emitting known-undeployable output.

## Technical report

### Root cause

The previous pipeline treated constructor data as untouched recovery material. Section detection also examined the end of the whole creation payload for Solidity CBOR metadata even though constructor arguments follow the compiler-generated creation bytecode. ABI words could therefore be mistaken for metadata, while the real argument suffix was reassembled unchanged. In the reported deployment this made all six recipient/token/amount rows recoverable by reading aligned words at the tail; no EVM analysis was necessary.

### Design and implementation

The fix has four cooperating parts:

1. **Exact section boundaries.** The complete caller-supplied runtime must occur exactly once in the deployment payload. Its start separates init from runtime, its own CBOR trailer is split as auxdata, and every byte after its end is classified as `ConstructorArgs`. This is byte-exact and works for static, dynamic, packed-looking, all-zero, and adversarial argument values without ABI guessing.

2. **Seed-derived masking.** The argument suffix is divided into 32-byte chunks and XOR-masked byte-for-byte. Masks are derived deterministically from the Azoth seed, a domain separator, and the argument length. Chunk order is shuffled, and each mask is synthesized with the existing arithmetic-chain vocabulary rather than stored as one direct key constant.

3. **Init-code decoding.** Azoth locates one exact Solidity-style `CODESIZE - creation_length` argument `CODECOPY`. It replaces bytes inside that basic block with a trampoline and appends a decoder to init code. The decoder performs the original copy, unmasks memory in seed-shuffled order, then replays the displaced original instructions. Existing init jump destinations do not move. Direct, PC-relative, XOR-split, and SUB-split trampoline forms are selected by seed and available space. PC-sensitive displaced blocks are rejected.

4. **Correct recovery.** Reassembly now distinguishes deployed suffixes such as CBOR auxdata from transaction-only constructor arguments. Runtime `CODECOPY`/`RETURN` lengths exclude the arguments, creation offsets account for decoder growth, and the constructor's original creation-length constant is patched. Immutable-reference offsets continue to be remapped after runtime transforms. The final payload is checked against the 24,576-byte EIP-170 runtime limit and 49,152-byte EIP-3860 initcode limit.

The transform is automatically applied when an argument suffix exists. Callers may pass a full creation payload to `-D`, or pass compiler creation bytecode plus `--constructor-args <HEX>`. Result metadata exposes `constructor_args_obfuscated`, `constructor_argument_bytes`, and `constructor_decoder_bytes` so release tooling can enforce that expected sensitive inputs were actually handled.

### Validation performed for this change

The following results are a historical validation snapshot for constructor masking, not a formal equivalence proof or a guarantee for arbitrary contracts and pass combinations.

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

The built-in campaign randomly varied seeds, constructor recipients and amounts, and transform selections. Its existing REVM oracle required every transformed payload whose original deployed successfully to deploy successfully as well. The focused differential test supplied the stronger byte-for-byte deployed-runtime comparison. Unsupported and ambiguous copy layouts have explicit rejection tests.

The verification crate is now optional and builds without Z3 by default. Its contract-equivalence API returns `Unsupported`; enabling the prototype `z3` feature does not turn these constructor tests into a mathematical equivalence proof.

### Benchmark

Fixture: the repository's Solidity 0.8.30 ERC20 escrow with a 160-byte constructor suffix. Measurements use a release build and REVM. Size/gas deltas compare the original creation payload with the constructor-mask-only result for one representative deterministic seed; decoder distribution and transform time cover 100 deterministic seeds.

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Creation payload | 9,129 B | 9,700 B | +571 B (+6.26%) |
| REVM deployment gas | 1,861,722 | 1,869,364 | +7,642 (+0.410%) |
| Intrinsic calldata gas | 139,224 | 146,608 | +7,384 (+5.30%) |
| Deployed runtime | baseline | byte-for-byte identical | 0 B |
| Verbatim 160-byte ABI suffix | present | absent | removed |

Across 100 seeds, decoder size averaged 569.7 bytes (433 minimum, 711 maximum), and masking averaged 124.1 microseconds per creation payload in the release benchmark. Cost grows approximately with the number of 32-byte chunks; these figures should not be extrapolated as measurements of the report's larger multi-row payload without benchmarking that exact fixture.

### Security boundary and rollout guidance

This mitigation closes the report's direct plaintext-suffix extraction path. It does not encrypt transaction calldata, hide values after the EVM decodes them, suppress storage/log/call/proof disclosures, remove Solidity CBOR metadata, or prevent dynamic/symbolic recovery. Teams requiring confidentiality from validators, archive nodes, or skilled reverse engineers need a cryptographic protocol change, which was explicitly outside this work.

For rollout experiments, require `constructor_args_obfuscated: true` whenever an expected deployment has constructor inputs, retain differential deployment and behavior testing for each contract/compiler/pass set, and treat a fail-closed unsupported-layout error as a release blocker. Re-run the benchmark on the exact payload because decoder overhead is argument-length dependent.
