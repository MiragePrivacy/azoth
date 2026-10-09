# Native EVM bytecode decoder

## Purpose and boundary

Azoth must understand instruction boundaries before it can build a control-flow graph or move
code. That operation is now performed entirely by `azoth-core`. The production path no longer
converts bytecode to third-party assembly text and parses that text back into instructions. This
removes an async boundary, a text-format dependency, duplicated opcode interpretation, and a class
of partial-result failures.

Heimdall is deliberately retained only in `azoth-analysis` for optional decompiler and diff views.
It is not a production dependency of `azoth-core`, `azoth-transform`, or `azoth-verification`.
The integration-test crate still reaches it transitively through `azoth-analysis`, but native
decoder tests have no direct Heimdall dependency or use. EOT is not a workspace dependency.

## Data flow

The production data flow is:

```text
hex/file input -> exact bytes -> native instruction stream -> section ownership -> CFG/IR
                                                |
                                                +-> assembly only on explicit diagnostic request
```

`crates/core/src/opcode.rs` is the single source of truth for byte-to-opcode mapping, canonical
names, immediate widths, stack inputs/outputs, and block-ending behavior. Fixed opcodes are
declared once in a macro table; `PUSH`, `DUP`, and `SWAP` families are derived from their byte
ranges. Checked encoding rejects impossible manually constructed values such as `PUSH(33)`.

`crates/core/src/decoder.rs` performs a linear byte walk. Each `Instruction` records its exact
program counter, opcode, and physically present `PUSH` bytes. `crates/core/src/encoder.rs` encodes
from that owned representation and never consults a copy of the original bytecode to guess what an
instruction meant. Checked encoding also rejects immediate data attached to any opcode other than
`PUSH1` through `PUSH32`, validates contiguous program counters, and bounds an immediate before
decoding it; it never silently drops malformed IR fields or allocates from an untrusted claimed
operand size.

## Two decoding modes

### Lossless blob decoding

`decode_bytes(&[u8])` accepts every byte sequence, including empty code. Unknown opcode bytes are
stored as `Opcode::UNKNOWN(byte)`, so decode followed by encode reproduces the exact input.

This mode is necessary for a complete deployment artifact. Solidity compiler CBOR is data, not
executable code, but its bytes can resemble opcodes and may end syntactically inside a `PUSH`
operand when the whole artifact is viewed as one linear stream. Rejecting that before section
detection would reject ordinary compiler output.

### Strict executable decoding

`decode_executable_bytes(&[u8])` adds one safety check: a final `PUSHn` must contain all `n`
immediate bytes. A short final `PUSH` is legal EVM code because missing bytes read as zero. It is
not safe for a relocator, however: appending or moving another instruction after it changes the
value consumed by the `PUSH`. Strict mode returns `Error::TruncatedPush` with the byte offset,
declared width, and available width instead of returning a usable partial stream.

The transformation pipeline first decodes the complete artifact losslessly, establishes exact
runtime and compiler-data boundaries, and then decodes the runtime again from its own first byte.
This second decode matters because creation code and deployed runtime are separate executions: a
`PUSH` in init data may consume bytes across the runtime boundary in the creation-code linear view,
while deployed execution still treats the first runtime byte as a fresh opcode. Runtime PCs are
rebased to their absolute offsets after this independent strict decode. Validators and transform
helpers operating on an already isolated executable slice call strict mode directly.

## Unknown bytes and `INVALID`

Byte `0xfe` has a named EVM meaning and is represented by `Opcode::INVALID`. Other unassigned bytes
remain `Opcode::UNKNOWN(original_byte)`. They are not collapsed to `INVALID`, because doing so
would destroy byte identity during reconstruction.

In legacy EVM execution both cases halt exceptionally. Azoth therefore ends a basic block at an
unknown byte, but it assigns no stack metadata to that byte. Any analysis that would need to model
an unknown operation must reject the input rather than assuming a zero stack effect.

## Protocol revision

The table targets the Ethereum mainnet Fusaka execution-layer revision, named Osaka in execution
specifications. It includes EIP-7939 `CLZ` at byte `0x1e` and all earlier active legacy opcodes.
EOF was removed from Osaka; bytes reserved by the withdrawn EOF proposals remain unknown in
legacy code. The table does not attempt to decode an EOF container.

Relevant specifications:

- [EIP-7607: Hardfork Meta - Fusaka](https://eips.ethereum.org/EIPS/eip-7607)
- [EIP-7939: Count leading zeros (`CLZ`)](https://eips.ethereum.org/EIPS/eip-7939)
- [Execution-spec-tests changelog: EOF removed from Osaka](https://github.com/ethereum/execution-spec-tests/blob/main/docs/CHANGELOG.md#v450---2025-05-14)

The fork target is intentionally explicit. A dependency upgrade can no longer change opcode
semantics implicitly, but a future network upgrade still requires a deliberate Azoth release.

## Updating for a future hard fork

For every fork that changes legacy bytecode interpretation:

1. Read the final EIP and the executable execution specification; do not copy an opcode list from
   a decompiler.
2. Add or modify the one table entry in `opcode.rs`, including exact stack inputs and outputs.
3. Update the known-byte and stack-effect oracle tests, mnemonic parsing, and terminal/control-flow
   classification when applicable.
4. Add official execution-spec vectors or differential cases for the new byte.
5. Decide whether the byte is valid in legacy code, an EOF/container-only byte, or unassigned.
6. Review every exhaustive opcode match in CFG, relationship, verification, and transform code.
   Unhandled known opcodes must fail closed where their semantics matter.
7. Rerun all round-trip, malformed-`PUSH`, REVM differential, fuzz, full workspace, Clippy, and
   release benchmark gates.
8. Bump the pipeline profile and deterministic golden vectors if the interpretation can affect an
   output or manifest.

Do not activate a proposed opcode before its target fork is finalized and scheduled. Conversely,
do not leave a newly active byte as `UNKNOWN`: that is byte-lossless, but downstream analysis would
conservatively reject contracts that use it.

## Verification and performance gates

The decoder test suite covers all 256 byte values, every `PUSH1` through `PUSH32` width, every
possible final truncation length, opcode-looking immediate data, stable serialization, checked-in
deployment/runtime artifacts, a deterministic 10,000-case arbitrary-byte corpus, and instruction
boundaries differential-tested against REVM.

Run the focused gates with:

```sh
cargo test --locked -p azoth-core
cargo test --locked -p azoth-tests core::decoder
cargo run --locked --release -p azoth-examples --bin decoder_benchmark
```

The benchmark emits machine-readable JSON and measures decoding separately from assembly
rendering at 10, 100, and 1,000 iterations. Compiler CBOR is excluded from the strict executable
measurement and its byte count is reported explicitly.
