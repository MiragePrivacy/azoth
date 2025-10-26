# Azoth
![Azoth](assets/azoth.jpg)

## What is Azoth?

Azoth is a deterministic EVM bytecode obfuscator designed to make Mirage's execution contracts indistinguishable from ordinary, unverified deployments on Ethereum. The name "[Azoth](https://www.wikiwand.com/en/articles/Azoth)" derives from medieval alchemy, where it referred to the universal solvent: a hypothetical substance capable of dissolving any material and serving as the essential agent of transformation.

## How does it work?

1. Dissection: decode the contract’s init/runtime layout, resolve sections, and build a control-flow graph of block bodies and jump targets.

2. Transformation: apply deterministic transformations (e.g dispatcher transforms, block shuffling etc.) that changes the structure of the bytecode without blowing gas or size limits.

3. Recovery: lower the rewritten runtime alongside untouched init/constructor data so the final bytecode stays deployable.

Azoth also incorporates a formal verification system that provides mathematical guarantees of functional equivalence between original and obfuscated contracts.

## Status

Azoth is under active development: the parsing pipeline, CFG builder, and several core transforms are in daily use, while additional passes, verification tooling, and resilience metrics are landing incrementally as we harden the stack for production-facing deployments.

## Getting Started

Azoth is available through a command-line interface. This could be used for local development, testing, and experimentation with bytecode obfuscation.

## Contributing

We welcome new transforms, analysis improvements, performance tuning, documentation, and bug fixes. See [CONTRIBUTING.md](CONTRIBUTING.md) for style and workflow guidelines.

## Acknowledgments
Azoth builds on years of research in program analysis, obfuscation, and blockchain privacy. We are grateful to the broader community whose work makes this project possible.
