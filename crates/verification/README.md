## azoth-verification

This crate contains an experimental SMT model for comparing original and camouflaged contracts. The snippets below describe intended properties, including execution behavior, final state, and gas bounds. Azoth’s current verification tooling does not establish full semantic equivalence. Use deployment and behavior tests to check the contracts and paths you depend on.

- Bisimulation
```smt
(assert (forall ((state State) (input Input))
    (= (execute-original state input)
       (execute-camouflaged state input))))
```
The model would compare traces for each input and state.

- State Equivalence
```smt
(assert (forall ((initial-state State) (transaction Tx))
    (= (final-state (execute-original initial-state transaction))
       (final-state (execute-camouflaged initial-state transaction)))))
```
The property compares final storage, balances, and contract state.

- Property Preservation
```smt
(assert (forall ((s State)) 
    (and (access-control-original s) 
         (access-control-camouflaged s))))
```
The property checks whether the same modeled access controls hold.

- Gas Bounds
```smt
(assert (forall ((tx Transaction))
    (<= (gas-used (execute-camouflaged tx))
        (* 1.15 (gas-used (execute-original tx))))))
```
The snippet illustrates a gas bound. Actual gas costs depend on the contract, input, and transforms.
