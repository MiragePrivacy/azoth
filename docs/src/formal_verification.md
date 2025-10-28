# Formal Verification

The `azoth-verification` crate provides a scaffold for proving that an obfuscated contract behaves exactly like the original one. It models bytecode semantics, encodes equivalence properties in SMT-LIB, and delegates solving to an SMT backend (Z3-compatible).

## Engine overview

- `FormalVerifier::prove_equivalence` is the main entry point. It extracts semantics from both versions of the bytecode, then constructs proof obligations for:
  - **Bisimulation** – step-by-step execution traces match.
  - **State Equivalence** – final storage/balance state is identical for any transaction.
  - **Property Preservation** – user-supplied security properties (`SecurityProperty`) continue to hold.
  - **Gas Bounds** – obfuscated execution stays within an acceptable overhead.
- Each obligation is represented as a `ProofStatement` that records the SMT query, solver verdict, and runtime.
- Results aggregate into a `FormalProof` tagged with the combined proof types.

## Current status

The infrastructure builds the SMT problems and plumbing, but the actual solver calls are still stubbed (`TODO` markers set `proven = true`). Integrating concrete semantics and feeding them to the solver is in progress. Until then, treat the proofs as scaffolding suitable for development/testing rather than production guarantees.

## Extending properties

`properties.rs` defines reusable arithmetic/security predicates. You can add project-specific invariants by extending the enum and teaching `to_smt_formula` how to render them. Once the solver integration is complete these formulas become part of the combined proof output.
