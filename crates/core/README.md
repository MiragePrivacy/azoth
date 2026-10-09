# Azoth Core

The `azoth-core` crate provides the fundamental building blocks for EVM bytecode analysis and transformation. This crate handles the essential stages of bytecode processing: decoding, analysis, intermediate representation generation, and re-encoding.

## Architecture

The core crate implements a multi-stage pipeline for bytecode processing:

1. **Bytecode Decoding** - Converts raw bytecode into structured instruction sequences
2. **Section Detection** - Identifies constructor, runtime, and auxiliary data sections
3. **Stripping** - Isolates runtime code from deployment artifacts
4. **CFG/IR Generation** - Builds control flow graphs with intermediate representation
5. **Encoding** - Reconstructs bytecode from transformed representations

## Native bytecode boundary

`azoth-core` owns its opcode model and decoder. The decoder walks bytes once, computes exact byte
offsets, and treats only `PUSH1` through `PUSH32` payloads as immediate data. It does not spawn an
async task, render assembly, or call Heimdall/EOT. Human-readable assembly is produced only when a
CLI or diagnostic caller explicitly requests it.

There are two intentionally different entry points:

- `decode_bytes` is total over arbitrary byte blobs and preserves every byte, including unknown
  opcodes and a final short `PUSH`. This mode is appropriate while section boundaries and compiler
  metadata are still being identified.
- `decode_executable_bytes` rejects a final `PUSH` whose declared immediate extends past the end of
  its executable section. The EVM would read missing bytes as zero, but moving or appending code
  would turn new bytes into part of that operand. Transform and validation callers therefore fail
  closed.

`INVALID` always means byte `0xfe`. Every other unassigned byte is represented as
`UNKNOWN(original_byte)` and re-encodes exactly; unknown executable operations are terminal
exceptional halts and have no invented stack effect. The opcode table is pinned to the current
Fusaka/Osaka legacy EVM, including `CLZ` at `0x1e`. Withdrawn EOF proposal bytes remain unknown in
legacy bytecode. See `docs/native-bytecode-decoder.md` for the complete maintenance contract.

## Stable identity and physical layout

`CfgIrBundle` deliberately separates a block's identity from its byte offset. `NodeIndex` remains
stable while `layout_order` describes physical emission order. A transform changes layout through
`set_layout_order`; `reindex_pcs` is the lowering step that assigns concrete offsets. This prevents
relationships from silently becoming stale every time a pass moves code.

`RelationshipIndex` is rebuilt and validated transactionally. For every block it records section
and section-region membership, predecessors/successors, roles, cluster membership, unresolved
control, position-sensitive opcodes, and typed code-pointer relocations. Fallthrough and false
branch edges create adjacency constraints. Those constraints are unioned into ordered clusters so
a layout pass cannot separate instructions whose behavior depends on physical adjacency.

Solidity legacy internal calls carry return addresses on the EVM stack. The relationship analyzer
tracks literal code pointers through reachable `PUSH`, `DUP`, `SWAP`, and modeled stack effects
across CFG edges. It keeps distinct caller contexts rather than erasing them at joins. Only origins
that resolve consistently become `CodePointerRelocation` records; unsupported operations,
conflicts, resource-limit exhaustion, or non-literal dynamic jumps stay unresolved. Layout-changing
passes must refuse such input.

## Equivalence boundary

Azoth rejects layout variation when runtime code observes code position, size, bytes, or hash via
`PC`, `CODESIZE`, `CODECOPY`, `EXTCODESIZE`, `EXTCODECOPY`, or `EXTCODEHASH`. Some external-code
operations might not target `address(this)`, but proving that requires value analysis the current
foundation does not yet provide. The conservative rejection is intentional: a changed bytecode
cannot preserve self-code observations exactly.
