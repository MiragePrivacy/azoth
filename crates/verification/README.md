# Azoth's Formal Verification Engine

The purpose of this verification system is to establish functional equivalence between original EVM bytecode and the bytecode produced after Azoth applies one or more obfuscation transforms. In this context, functional equivalence means that the transformed contract preserves the observable behavior of the original contract under the chosen EVM semantics, including execution outcome, returned data, and resulting state changes.

Its role is to justify that Azoth's transformations preserve behavior beyond the concrete cases exercised by testing, so that semantic preservation becomes a property the pipeline can defend rather than merely sample. The verification engine therefore exists as the correctness foundation for accepting or rejecting transformed bytecode.
