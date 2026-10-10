## azoth-verification

This crate is an experimental foundation for future equivalence verification. It does **not** currently provide a mathematical guarantee that original and obfuscated contracts behave identically.

## Current safety behavior

- `FormalVerifier::prove_equivalence` returns `Error::Unsupported` until complete proof obligations and a sound EVM semantics exist.
- An empty set of proof statements is invalid.
- Unsupported or malformed SMT syntax is rejected rather than approximated as `true`.
- A solver `unknown` result is an error, never evidence of equivalence.
- Callers must not present `FormalProof` data structures as proof of equivalence unless they were produced by a future sound verifier.

## Optional Z3 backend

Z3 is optional and disabled by default, allowing the workspace to build without system Z3 headers or libraries. Enable the prototype backend explicitly:

```bash
cargo test -p azoth-verification --features z3
```

The backend currently accepts only a deliberately small assertion subset. Formula generation remains scaffolding and is not connected to a production equivalence claim.

## Required work before verification can be enabled

- A complete 256-bit EVM execution model with calls, logs, reverts, storage, balances, environmental inputs, and gas semantics.
- Relational handling for intentional selector and storage-layout mappings.
- Proofs formulated as the absence of a counterexample, with `unsat` required for success.
- Independent known-equivalent and known-inequivalent fixtures, including expected counterexamples.
- Resource limits and explicit failure on timeout or indeterminate solver status.
