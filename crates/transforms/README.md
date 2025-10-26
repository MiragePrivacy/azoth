# Azoth Transforms

The `azoth-transform` crate implements the obfuscation transformations that enhance bytecode complexity and resistance to analysis. This crate provides a pluggable architecture for applying various obfuscation techniques while maintaining semantic equivalence.

## Architecture

The transforms crate implements a pass-based architecture where each transformation operates on the CFG/IR representation:

1. **Pass Interface** - Standardized transformation interface for modularity
2. **Transformation Passes** - Individual obfuscation techniques
3. **Metrics Integration** - Continuous evaluation during transformation
4. **Rollback Support** - Automatic rejection of ineffective passes

## Current Transforms

### Shuffle (`shuffle.rs`)

Reorders basic blocks within the CFG while updating jump targets to maintain correctness. Simple block-level randomization that changes program layout without affecting execution.

Example

```assembly
Original -> 0x60015b6002
Shuffled -> 0x5b60026001
```

### Opaque Predicate (`opaque_predicate.rs`)

Injects always-true (or always-false) predicates built from cheap arithmetic or constant-equality (e.g., XOR + ISZERO or EQ on identical constants). Adds dummy control-flow that never influences observable behavior but explodes CFG shape.

Example

Original bytecode: 0x6001600260016003 (8 bytes, 4 instructions, 1 block)

```assembly
PUSH1 0x01
PUSH1 0x02  
PUSH1 0x01
PUSH1 0x03
```

After OpaquePredicate: (~80–100 bytes, ~12 instructions, 3 blocks; seed-dependent)

```assembly
// Original block (now with predicate appended)
PUSH1 0x01
PUSH1 0x02
PUSH1 0x01
PUSH1 0x03
PUSH32 C                // Random 32-byte constant
PUSH32 C                // Same constant
XOR                     // 0
ISZERO                  // -> 1 (true)
PUSH2 true_pc
JUMPI
JUMPDEST                // Join point (false path)
JUMP false_pc

// New true_label block
JUMPDEST                // True branch target (always taken)
// execution continues to original fallthrough

// New false_label block  
JUMPDEST                // False branch target (never reached)
PUSH1 0x00
JUMP <original_fallthrough>  // Dead code path
```

Changes: +80-100 bytes, splits 1 block into 3, adds always-true branching that never affects execution but complicates CFG analysis.

### Jump Address Transformer (`jump_address_transformer.rs`)

Splits jump targets into arithmetic operations. Replaces PUSH1 0x42 JUMP with PUSH1 0x20 PUSH1 0x22 ADD JUMP where the values sum to the original target.

Example

Original bytecode: 0x60085760015b00 (7 bytes, 5 instructions, 3 blocks)

```assembly
PUSH1 0x08    // Direct jump target
JUMPI         // Conditional jump to 0x08
PUSH1 0x01    // Fallthrough path  
JUMPDEST      // Jump destination at 0x08
STOP
```

After JumpAddressTransformer: 0x60046004015760015b00 (10 bytes, 7 instructions, 3 blocks)

```assembly
PUSH1 0x04    // First part of split target
PUSH1 0x04    // Second part (0x04 + 0x04 = 0x08)
ADD           // Compute original target at runtime
JUMPI         // Conditional jump to computed value
PUSH1 0x01    // Fallthrough path unchanged
JUMPDEST      // Same jump destination  
STOP
```

Changes: +3 bytes, +2 instructions; replaces direct 0x08 with 0x04 + 0x04 via ADD. Net +6 gas (2 extra PUSH1s + ADD – original single PUSH1).

### Function Dispatcher (`function_dispatcher.rs`)

Replaces Solidity-style dispatchers with a cryptographically hardened version that is resistant to selector fingerprinting and pattern-based detection.

#### Key Features

* **Token Derivation**: Uses cryptographic `keccak256(secret || selector)[:4]` to generate fixed 4-byte tokens
* **Disguised Extraction**: Replaces obvious calldata patterns with obfuscated arithmetic (e.g., `XOR`, `SUB`, `MOD`, `MSTORE/MLOAD`)
* **SHR-Based Extraction**: Extracts tokens using right-shift operations that work correctly even when calldata includes function arguments
* **Comparison Replacement**: Replaces all `PUSH4 <selector>` checks with `PUSH4 <token>`
* **Shuffled Order**: Randomizes comparison order to prevent pattern recognition
* **Internal Call Updates**: Updates all internal `PUSH4 selector; CALL` instructions to use `PUSH4 token; CALL`

#### Token Extraction Method

The dispatcher uses a right-shift (SHR) operation to extract the 4-byte token from calldata:

1. **CALLDATALOAD(0)** loads the first 32 bytes with the selector left-aligned
2. **SHR 224** shifts right by 28 bytes (224 bits), moving the token to the low position
3. The shift automatically discards any function arguments, leaving only the 4-byte token

This approach works correctly even when calldata includes arguments:

```
Calldata for bond(1000):
  0x500b6840 00000000000000000000000000000000000000000000000000000000000003e8
  │────────│ ──────────────────────────────────────────────────────────────│
   4-byte          32-byte argument (uint256 = 1000)
   token

CALLDATALOAD(0): 0x500b684000000000000000000000000000000000000000000000000000000000
SHR 224:         0x00000000000000000000000000000000000000000000000000000000500b6840
                                                                           └──────┘
                                                                          4-byte token
```

Since we use **fixed 4-byte tokens**, the SHR operation alone is sufficient. The right-shift automatically removes all argument bytes, leaving only the token for comparison. No additional masking is needed.

#### Example Transformation

**Original dispatcher:**

```assembly
PUSH1 0x00           ; offset 0
CALLDATALOAD         ; load calldata[0..31]
PUSH1 0xe0           ; 224 bits
SHR                  ; extract selector
DUP1
PUSH4 0x7ff36ab5     ; selector for balanceOf
EQ
PUSH1 0x1a
JUMPI
DUP1
PUSH4 0xa9059cbb     ; selector for transfer
EQ
PUSH1 0x21
JUMPI
```

**Obfuscated dispatcher:**

```assembly
PUSH1 0x39
PUSH1 0x39
XOR                  ; disguised 0x00 (random arithmetic)
CALLDATALOAD         ; load calldata[0..31]
PUSH1 0xe0           ; 224 bits
SHR                  ; extract 4-byte token from left
DUP1
PUSH4 0x1278bea5     ; cryptographic token for 0xa9059cbb (transfer)
EQ
PUSH1 0x30
JUMPI
DUP1
PUSH4 0xa93a3604     ; cryptographic token for 0x7ff36ab5 (balanceOf)
EQ
PUSH1 0x29
JUMPI
PUSH1 0x00
DUP1
REVERT               ; default case
```

#### Changes

* **Original selectors completely replaced** with cryptographically-derived tokens
* **Calldata offset computation disguised** using random arithmetic operations
* **Comparison order randomized** to prevent sequential pattern matching
* **Function bodies unchanged** - they still read arguments from offset 4+ as normal
* **Jump targets automatically updated** to maintain semantic equivalence

This makes function selectors unrecognizable to static analysis tools and completely eliminates selector-based fingerprinting, while maintaining full compatibility with standard ABI encoding for function arguments.

### Transform Interface

```rust
#[async_trait]
pub trait Transform: Send + Sync {
    fn name(&self) -> &'static str;
    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError>;
}
```

### Pass Execution

Consumers typically orchestrate transforms themselves. A minimal driver looks like:

```rust
let mut rng = seed.create_deterministic_rng();
for transform in transforms {
    if transform.apply(&mut cfg_ir, &mut rng)? {
        // optionally recompute metrics, log deltas, etc.
    }
}
```

The transforms operate on `CfgIrBundle` structures and can be combined with
metrics from `azoth-analysis` to evaluate effectiveness.
