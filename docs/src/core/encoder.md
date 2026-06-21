# Encoder

Once transforms have rewritten the CFG, the encoder module turns the updated instruction stream back into raw bytes. `encode` walks each `Instruction`, emits the opcode byte, and for PUSH instructions validates and appends the immediate payload. When the decoder previously marked an opcode as `INVALID` because Heimdall could not name it, the encoder preserves the original byte by looking up the program counter in the reference bytecode instead of emitting `0xfe`, ensuring round-trips do not corrupt unknown instructions.

The module also exposes `rebuild`, a thin wrapper over `CleanReport::reassemble`, which stitches the modified runtime back together with the removed sections (init, constructor args, auxdata) recorded by `strip`. Together these functions guarantee that transforms can operate at the instruction level while still producing a deployable payload after rewriting control flow.
