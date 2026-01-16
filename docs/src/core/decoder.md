# Decoder

The decoder module is the first stop in the pipeline: it normalizes raw hex or file input, runs Heimdall to disassemble the byte stream, and turns the output into structured `Instruction` values. Each instruction records the program counter, parsed opcode (mapped to `eot::UnifiedOpcode`), and any immediate operand so later stages can reason about stack effects or rewrite PUSH data.

`decode_bytecode` returns four artifacts in one call:
- the instruction stream,
- `DecodeInfo` metadata (length, Keccak-256 hash, and whether the source was inline hex or a file),
- the raw assembly text for debugging, and
- the original byte vector.
Parsing is intentionally strict—missing PCs, malformed opcodes, and empty output produce explicit errors—because downstream modules assume the stream is well formed. Unknown opcodes are tagged as `Opcode::UNKNOWN` or `Opcode::INVALID` placeholders; the encoder relies on the preserved program counter to recover the original byte when rebuilding.
