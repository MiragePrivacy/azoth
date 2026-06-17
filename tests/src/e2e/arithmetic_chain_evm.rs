//! Differential test: ArithmeticChain Rust model vs real EVM semantics.
//!
//! Background. A `collect()` invocation obfuscated under seed
//! `b1314f5c5063267ec70a9b9bb6f3d6b0cfb96b0f54773b3e534f54cd92caa5b4`
//! reverted on mainnet with `WrongEventSignature()`: the ERC20 `Transfer`
//! event topic constant the contract compares against
//! (`0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`)
//! was reconstructed by an ArithmeticChain to the wrong value at runtime.
//!
//! ArithmeticChain replaces a `PUSH <const>` with a sequence of loads and
//! arithmetic ops that recompute `const`. The initial values are derived by
//! `ArithmeticOp::compute_backward`, and the transform asserts correctness
//! with `evaluate_forward` (chain.rs / reverse.rs). But that forward
//! evaluation runs the *Rust model* (`wrapping_mul` / `wrapping_div` in
//! types.rs), which only multiplies/divides by the low byte `b[31]`. The
//! compiler (compiler.rs) emits the real EVM `MUL` / `DIV` opcodes, which are
//! full 256-bit operations. For any chain containing a MUL or DIV the two
//! disagree whenever the operand's high bytes are non-zero, so the on-chain
//! reduction lands on a different constant than the backward computation
//! promised. The in-process `debug_assert_eq!` never catches it because it
//! checks the model against itself.
//!
//! This test compiles each generated chain to standalone bytecode, executes
//! it on REVM, and asserts the EVM result equals the backward target.

use azoth_core::encoder::encode;
use azoth_core::seed::Seed;
use azoth_core::Opcode;
use azoth_transform::arithmetic_chain::{
    compile_chain_inline, evaluate_forward, generate_chain, ArithmeticOp, ChainConfig,
};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::context::result::{ExecutionResult, Output};
use revm::context::{ContextTr, TxEnv};
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};

/// The seed that produced the failing mainnet `collect()`.
const FAILING_SEED: &str = "b1314f5c5063267ec70a9b9bb6f3d6b0cfb96b0f54773b3e534f54cd92caa5b4";

/// ERC20 `Transfer(address,address,uint256)` event topic constant. This is
/// the value the escrow's `collect()` reconstructs and compares; corrupting
/// it triggers `WrongEventSignature()`.
const TRANSFER_TOPIC: [u8; 32] =
    hex_literal::hex!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// Wrap a compiled chain in standalone runtime bytecode that stores the
/// reduced value to memory and returns it: `<chain> PUSH0 MSTORE PUSH1 0x20
/// PUSH0 RETURN`. The chain leaves exactly one 32-byte word on the stack.
fn chain_runtime_bytecode(chain_instrs: &[azoth_core::decoder::Instruction]) -> Result<Vec<u8>> {
    use azoth_core::decoder::Instruction;

    let mut instrs = chain_instrs.to_vec();
    instrs.extend([
        Instruction {
            pc: 0,
            op: Opcode::PUSH0,
            imm: None,
        },
        Instruction {
            pc: 0,
            op: Opcode::MSTORE,
            imm: None,
        },
        Instruction {
            pc: 0,
            op: Opcode::PUSH(1),
            imm: Some("20".to_string()),
        },
        Instruction {
            pc: 0,
            op: Opcode::PUSH0,
            imm: None,
        },
        Instruction {
            pc: 0,
            op: Opcode::RETURN,
            imm: None,
        },
    ]);

    encode(&instrs, &[]).map_err(|e| eyre!("encode failed: {:?}", e))
}

/// Deploy `runtime` as a contract whose body simply returns `runtime`, then
/// call it and return the 32-byte output. Uses a minimal init prefix that
/// CODECOPYs the runtime out of the deployment payload.
fn run_runtime(runtime: &[u8]) -> Result<[u8; 32]> {
    // init code: copy `runtime` (appended after this 14-byte prefix) to mem
    // and RETURN it.
    //   PUSH2 len; PUSH1 0x0e; PUSH1 0x00; CODECOPY; PUSH2 len; PUSH1 0x00; RETURN
    // 3 + 2 + 2 + 1 + 3 + 2 + 1 = 14 bytes, so runtime starts at offset 0x0e.
    const PREFIX_LEN: u8 = 14;
    let len = runtime.len();
    let mut init = Vec::new();
    init.push(0x61); // PUSH2
    init.extend_from_slice(&(len as u16).to_be_bytes());
    init.push(0x60); // PUSH1
    init.push(PREFIX_LEN);
    init.push(0x60); // PUSH1
    init.push(0x00);
    init.push(0x39); // CODECOPY
    init.push(0x61); // PUSH2
    init.extend_from_slice(&(len as u16).to_be_bytes());
    init.push(0x60); // PUSH1
    init.push(0x00);
    init.push(0xf3); // RETURN
    debug_assert_eq!(init.len(), PREFIX_LEN as usize);
    init.extend_from_slice(runtime);

    let deployer = Address::from([0x42u8; 20]);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        deployer,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    let deploy = evm
        .transact(TxEnv {
            caller: deployer,
            gas_limit: 30_000_000,
            kind: TxKind::Create,
            data: Bytes::from(init),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .map_err(|e| eyre!("deploy failed: {:?}", e))?;
    evm.db_mut().commit(deploy.state.clone());
    let addr = match deploy.result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(addr)),
            ..
        } => addr,
        other => return Err(eyre!("deploy did not create contract: {:?}", other)),
    };

    let call = evm
        .transact(TxEnv {
            caller: deployer,
            gas_limit: 30_000_000,
            kind: TxKind::Call(addr),
            data: Bytes::new(),
            value: U256::ZERO,
            nonce: 1,
            ..Default::default()
        })
        .map_err(|e| eyre!("call failed: {:?}", e))?;
    let out = match call.result {
        ExecutionResult::Success {
            output: Output::Call(bytes),
            ..
        } => bytes,
        other => return Err(eyre!("call did not succeed: {:?}", other)),
    };
    let mut result = [0u8; 32];
    if out.len() == 32 {
        result.copy_from_slice(&out);
    } else {
        return Err(eyre!("expected 32-byte output, got {}", out.len()));
    }
    Ok(result)
}

/// Drive `n` chains off the production-derived RNG for the failing seed, and
/// for each: assert the Rust forward model matches the target (sanity), then
/// assert the EVM execution of the compiled chain matches the target.
///
/// The first target is the real ERC20 Transfer topic; the rest are derived
/// deterministically so the battery exercises a range of constants.
#[test]
fn arithmetic_chain_evm_matches_backward_target() -> Result<()> {
    let seed = Seed::from_hex(&format!("0x{FAILING_SEED}")).expect("valid seed");
    let mut rng = seed.create_deterministic_rng();
    let config = ChainConfig::default();

    let mut targets: Vec<[u8; 32]> = vec![TRANSFER_TOPIC];
    // Add structured targets that stress MUL/DIV high bytes.
    for i in 0..64u8 {
        let mut t = TRANSFER_TOPIC;
        t[0] ^= i;
        t[31] = t[31].wrapping_add(i);
        targets.push(t);
    }

    let mut model_mismatches = 0usize;
    let mut evm_mismatches = Vec::new();

    for (idx, target) in targets.iter().enumerate() {
        let chain = generate_chain(*target, &config, &mut rng);

        // The Rust model must round-trip (this is what the transform asserts).
        let model = evaluate_forward(&chain.initial_values, &chain.operations);
        if model != *target {
            model_mismatches += 1;
        }

        // Now the real EVM.
        let instrs = compile_chain_inline(&chain);
        let runtime = chain_runtime_bytecode(&instrs)?;
        let evm_result = run_runtime(&runtime)?;

        if evm_result != *target {
            let ops: Vec<&str> = chain
                .operations
                .iter()
                .map(|o| match o {
                    ArithmeticOp::Add => "ADD",
                    ArithmeticOp::Sub => "SUB",
                    ArithmeticOp::Xor => "XOR",
                    ArithmeticOp::And(_, _) => "AND",
                    ArithmeticOp::Or(_, _) => "OR",
                    ArithmeticOp::Mul => "MUL",
                    ArithmeticOp::Div(_) => "DIV",
                })
                .collect();
            evm_mismatches.push((idx, hex::encode(target), hex::encode(evm_result), ops));
        }
    }

    eprintln!(
        "model self-consistency mismatches: {} / {}",
        model_mismatches,
        targets.len()
    );
    eprintln!(
        "EVM vs target mismatches: {} / {}",
        evm_mismatches.len(),
        targets.len()
    );
    for (idx, target, got, ops) in &evm_mismatches {
        eprintln!("  target[{idx}]=0x{target}\n    evm   =0x{got}\n    ops   ={ops:?}");
    }

    if !evm_mismatches.is_empty() {
        return Err(eyre!(
            "{} of {} chains diverged between the Rust model and the EVM \
             (ArithmeticChain MUL/DIV model only uses the low operand byte; \
             the compiler emits full 256-bit EVM MUL/DIV)",
            evm_mismatches.len(),
            targets.len()
        ));
    }

    Ok(())
}
