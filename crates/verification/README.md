## azoth-verification

This crate provides mathematical guarantees that camouflaged smart contracts behave identically to their original versions. When we camouflage bytecode, we fundamentally alter its structure while preserving functionality. Formal verification uses mathematical proofs to ensure this preservation is complete and correct.

Traditional testing can only verify specific cases, but smart contracts must handle infinite input combinations. A single undetected difference between original and camouflaged contracts could compromise security or functionality. Formal verification provides mathematical certainty that the contracts are equivalent for **all possible inputs**, not just tested ones.

We use SMT-LIB (Satisfiability Modulo Theories) as our mathematical language to express contract properties, and Z3 theorem prover to automatically verify these properties. This serves as link between low-level bytecode and high-level mathematical reasoning.

Now our verification establishes four key equivalence properties:

- Bisimulation
```smt
(assert (forall ((state State) (input Input))
    (= (execute-original state input)
       (execute-camouflaged state input))))
```
For EVERY input and state, both contracts produce the same execution trace.

- State Equivalence
```smt
(assert (forall ((initial-state State) (transaction Tx))
    (= (final-state (execute-original initial-state transaction))
       (final-state (execute-camouflaged initial-state transaction)))))
```
After ANY transaction, the storage, balances, and contract state are identical between original and camouflaged versions.

- Property Preservation
```smt
(assert (forall ((s State)) 
    (and (access-control-original s) 
         (access-control-camouflaged s))))
```
ALL security properties satisfied by original are satisfied by camouflaged.

- Gas Bounds
```smt
(assert (forall ((tx Transaction))
    (<= (gas-used (execute-camouflaged tx))
        (* 1.15 (gas-used (execute-original tx))))))
```
For ANY transaction, camouflaged version uses at most 15% more gas.
