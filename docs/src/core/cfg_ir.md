# Control-Flow Graph IR

The `cfg_ir` module turns decoded runtime instructions into a stable directed graph that every transform mutates. `build_cfg_ir` receives the runtime slice, detected sections, and `CleanReport` metadata; it splits instructions into basic blocks, wires edges based on control flow, annotates jump encodings, and records runtime bounds so that transforms know which blocks belong to the deployed code.

Key data structures include:
- `Block`/`BlockBody`: graph nodes that store the first program counter, copied instructions, stack height, and control descriptor.
- `BlockControl` and `JumpTarget`: describe how a block exits (fallthrough, branch, terminal) and whether immediates are absolute PCs, runtime-relative offsets, or symbolic.
- `CfgIrBundle`: the container returned to transforms, holding the graph, PC-to-node map, detected sections, original bytecode, runtime bounds, and a trace log of structural edits for downstream tooling.

During assembly the module validates that every `JUMPDEST` begins a block, adds entry/exit sentinels, emits edges with semantic labels (`Fallthrough`, `Jump`, `BranchTrue`, `BranchFalse`), and assigns simple SSA-style identifiers for stack tracking. Helper routines snapshot graph state and compute diffs so transforms can report their mutations and the encoder can rebuild a coherent runtime after rewriting blocks.
