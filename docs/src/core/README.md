# Core Crate

The Azoth core crate implements the deterministic pipeline that turns raw bytecode into a transformable control-flow graph and then reassembles the final artifact. It exposes reusable building blocks that other crates (CLI, transforms, verification) consume so every stage shares the same understanding of program layout.

At a high level the crate:

- Normalizes and decodes bytecode into structured instructions (`decoder`).
- Detects init/runtime/auxiliary regions and dispatcher metadata (`detection`).
- Produces a cleaned runtime blob while preserving reassembly data (`strip`).
- Constructs the control-flow graph intermediate representation that powers transforms (`cfg_ir`).
- Encodes modified instruction streams back into deployable bytecode (`encoder`).

Each module is documented in the following pages to show how they interlock and which data structures they introduce.
