//! End-to-end proof-flow tests for the escrow `collect()` path using a
//! real-world receipt proof fixture.
//!
//! The fixture is lifted from `examples/escrow-bytecode/test/Proof.t.sol`
//! (see `testCollectWithTransferProof_EIP1559`). The baseline flow verifies
//! that the fixture and REVM harness are valid end-to-end: constructor funding,
//! bonding, ABI-decoding the `ReceiptProof` struct, block-header parsing, MPT
//! receipt inclusion, and receipt-log validation. The obfuscated flow then runs
//! the same scenario against Azoth output to characterize where transforms
//! currently break that path.

use super::{
    build_standard_calldata, mock_token_bytecode, prepare_bytecode_with_args, EscrowMappings,
    ObfuscatedCaller, ESCROW_BOND, ESCROW_COLLECT, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
    ESCROW_CONTRACT_RUNTIME_BYTECODE,
};
use azoth_core::seed::Seed;
use azoth_transform::arithmetic_chain::ArithmeticChain;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::push_split::PushSplit;
use azoth_transform::slot_shuffle::SlotShuffle;
use azoth_transform::string_obfuscate::StringObfuscate;
use azoth_transform::Transform;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use hex_literal::hex;
use revm::bytecode::Bytecode;
use revm::context::journal::Journal;
use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, CfgEnv, ContextTr, TxEnv};
use revm::database::InMemoryDB;
use revm::inspector::Inspector;
use revm::interpreter::interpreter_types::Jumps;
use revm::primitives::{Address, Bytes, TxKind, B256, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, InspectEvm, MainBuilder, MainContext};

/// Number of most-recent `(pc, opcode)` pairs kept by [`RingTracer`].
///
/// Sized to comfortably span a full `collect()` invocation's trailing
/// execution window — empirically ~300 opcodes between the chain reduction
/// at the Transfer-topic comparison and any late-path revert — so that when
/// a `Halt(InvalidJump)` or late `Revert` fires, the buffer contains every
/// step from the last function boundary up to and including the failing
/// instruction. Larger capacities don't meaningfully help (the bug is
/// almost always in the last dozen steps) and smaller ones have missed
/// the chain emission region in practice.
const RING_CAPACITY: usize = 400;

thread_local! {
    /// Backing store for [`RingTracer`]. Using a `thread_local!` rather
    /// than owning the buffer on the tracer itself lets the `inspect(...)`
    /// call consume a fresh zero-sized `RingTracer` by value while still
    /// leaving the captured trace readable by [`dump_ring_buffer`] after
    /// the EVM returns.
    static RING_BUFFER: std::cell::RefCell<std::collections::VecDeque<(usize, u8)>> =
        std::cell::RefCell::new(std::collections::VecDeque::with_capacity(RING_CAPACITY));
}

/// REVM step inspector that records the last [`RING_CAPACITY`]
/// `(pc, opcode)` pairs executed before control leaves the interpreter.
///
/// Gated by the `TRACE_COLLECT` environment variable (see
/// [`execute_collect_proof_flow`]), this is a diagnostic aid for
/// regression probes in this file: when one of the `collect()` transform
/// tests halts with `InvalidJump` or reverts through an unfamiliar custom
/// error selector, setting `TRACE_COLLECT=1` and re-running the failing
/// test prints the most recent steps to stderr so the exact failure PC
/// and the opcodes leading up to it can be cross-referenced against a
/// disassembly of the deployed bytecode. In particular this is what
/// pinpointed PushSplit's cross-block return-address PUSH (a JUMP at
/// runtime PC `0x07be` consuming a stale PUSH2 from `0x07a6`) and the
/// ArithmeticChain CODECOPY chain emission block (`0x1b68..0x1bfe`).
///
/// The inspector itself is a zero-sized type — all captured state lives
/// in the thread-local [`RING_BUFFER`] — so constructing one is free and
/// passing it to `evm.inspect(...)` does not interfere with non-tracing
/// runs that go through `evm.transact(...)`.
struct RingTracer;

impl Inspector<Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, ()>>
    for RingTracer
{
    fn step(
        &mut self,
        interp: &mut revm::interpreter::Interpreter,
        _context: &mut Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, ()>,
    ) {
        let pc = interp.bytecode.pc();
        let opcode = interp.bytecode.opcode();
        RING_BUFFER.with(|buf| {
            let mut buf = buf.borrow_mut();
            if buf.len() == RING_CAPACITY {
                buf.pop_front();
            }
            buf.push_back((pc, opcode));
        });
    }
}

/// Print the current contents of [`RING_BUFFER`] to stderr under the
/// given test label. Called after an inspected `collect()` transaction
/// so the trailing execution window is visible regardless of whether
/// the tx succeeded, reverted, or halted.
fn dump_ring_buffer(label: &str) {
    RING_BUFFER.with(|buf| {
        let buf = buf.borrow();
        eprintln!("[{label}] RingTracer last {} steps:", buf.len());
        for (pc, opcode) in buf.iter() {
            eprintln!("  pc=0x{pc:04x} opcode=0x{opcode:02x}");
        }
    });
}

const TARGET_BLOCK_NUMBER: u64 = 9_084_468;
const TARGET_BLOCK_HASH: B256 = B256::new(hex!(
    "490a3fc0b0c2170b55ca18ce6c73fc1af50ebe0931b525a3510c048f2b428617"
));

const PROOF_TOKEN: Address = Address::new(hex!("Be41a9EC942d5b52bE07cC7F4D7E30E10e9B652A"));
const PROOF_RECIPIENT: Address = Address::new(hex!("658D9C76ff358984D6436eA11ee1eda08894C818"));
const PROOF_EXECUTOR: Address = Address::new(hex!("E1A9d9C9abB872dDEF70A4d108Fd8fc3c7cE4dC4"));

const TRANSFER_AMOUNT: u64 = 0x017d_7840;

const REWARD_AMOUNT: u128 = 500_000_000_000_000_000_000;
const PAYMENT_AMOUNT: u128 = 500_000_000_000_000_000_000;
const BOND_AMOUNT: u128 = 250_000_000_000_000_000_000;

const BLOCK_HEADER_HEX: &str = "f90284a038d8a229ef5ed7e4c0ae36034362b7ed00d49d57f1b31e60190befaeca73ff37a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347945cc0dde14e7256340cc820415a6022a7d1c93a35a02624c60133f2c08e34990e93b66aaa3a72b135f77cf00c043a35caebf39ae54ba00ca3a794d63539a566e6a5d8cfbbf9c0e603022ae866248e7006710fde83eb12a025996241a33fe6ed92599ff80b2021d5f60993913b9e0552762d03104aa40996b901000224180066041c1200807d10a642c8950918d3200d0230551880a124009a5d50419a900270c0032603ab204001208000d54911110080ac20840900227e2841101224280202206149000c105cc0081020910100c58244804009828403e0828040020e400922215048954cc0d184112c8298ca001044584c1b20544050101c004008c028ca30523c142041038022228c0c514405110000c00b0052904914b46cc04209ba00088100812b005a054068204802b2008882009888a06022b0e02024254a110846880000008447002000d692c832540005a8a4001011800996203969225018901428000820dc121002c0a10042a05910a50208414404c852460012000380838a9e34840393870084011657b98468b0bba099d883010f0b846765746888676f312e32342e32856c696e7578a07e4379dbae3938a4b37b5b2cee386d2d9211adb64f4e3e2639ce9a4a721ea446880000000000000000826d7ba07f589ddc82719228971df748642152411fdd81592b880c2d913aeab7c415c204830a00008405580000a08744f3f453b537272189a1a10202fbfa9fb991fa1f431a5dd96cb6255ea39c58a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const RECEIPT_RLP_HEX: &str = "02f901a801840114e0a3b9010000000000000000000000000000000880000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000010000000000000200000000000004000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000001000000000000000000000000000f89df89b94be41a9ec942d5b52be07cc7f4d7e30e10e9b652af863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000e1a9d9c9abb872ddef70a4d108fd8fc3c7ce4dc4a0000000000000000000000000658d9c76ff358984d6436ea11ee1eda08894c818a000000000000000000000000000000000000000000000000000000000017d7840";
const PROOF_NODES_HEX: &str = "f903c2b90114f90111a0521cc12bd9690d6917c873bca358761ebe614bcdda311ae96a565eb3541fb976a0b02184e8a0f42f8fc9334201f746a9baff3de9e8f41eea0e18fad0548b97e764a0bf9522de2efbf1ecd763d7d07c04b9579780e4dfcef4cd95d28941645d47b1cda09a0a1fe35afc2e59684ff2f5daa1c73b86cdcdae91e3368474eb9022bda2d063a013bdd2da4c785610d0f05060fe681f5e477f50c69194c0e28136e69206563696a05560234c78f21ba3a9aae7cba7ae577bfef05933de718331d878c739507efa02a0d845d6731dfdf289204a3a1ffe46af371ad170b4daac166e62904542c6f878be80a0e58215be848c1293dd381210359d84485553000a82b67410406d183b42adbbdd8080808080808080b8f3f8f1a05de6d331fd323cecf969809160b38063ad1e7a57621535a2c9503cf09ef18e74a0020c21c6134f94c5450c428e2dd9c92e1f027453e4ce8a329ba860fd7b8609e7a0b9f56b8bb529ada6000134c7eaf30976bdde0677b22ef29fbe235df54205cb83a0f57f302c4dd5c6a92c1f8349d86e89e0fe628640114cbc39417dcfc4a30ac43da0781c51cf0bce52b41a3304f2a8e588127c811c0c69988cd84527721c7f39e8eea0a2d9ebe7b6cb704af1eed8dd7524ee7d1b762e83e602f07053a93c2c230a91b7a052dca8e0b775939ceafe9bceb2bb92fd94196bc96e377721bd1e58899065341080808080808080808080b901b3f901b020b901ac02f901a801840114e0a3b9010000000000000000000000000000000880000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000010000000000000200000000000004000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000001000000000000000000000000000f89df89b94be41a9ec942d5b52be07cc7f4d7e30e10e9b652af863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000e1a9d9c9abb872ddef70a4d108fd8fc3c7ce4dc4a0000000000000000000000000658d9c76ff358984d6436ea11ee1eda08894c818a000000000000000000000000000000000000000000000000000000000017d7840";
const RECEIPT_PATH_HEX: &str = "62";

fn abi_encode_bytes_field(data: &[u8]) -> (Vec<u8>, usize) {
    let len = data.len();
    let padded_len = len.div_ceil(32) * 32;
    let total_size = 32 + padded_len;
    let mut encoded = Vec::with_capacity(total_size);
    encoded.extend_from_slice(&U256::from(len).to_be_bytes::<32>());
    encoded.extend_from_slice(data);
    encoded.resize(total_size, 0);
    (encoded, total_size)
}

fn build_collect_calldata(
    selector: [u8; 4],
    block_header: &[u8],
    receipt_rlp: &[u8],
    proof_nodes: &[u8],
    receipt_path: &[u8],
    log_index: U256,
    target_block_number: U256,
) -> Bytes {
    let (bh_enc, bh_size) = abi_encode_bytes_field(block_header);
    let (rr_enc, rr_size) = abi_encode_bytes_field(receipt_rlp);
    let (pn_enc, pn_size) = abi_encode_bytes_field(proof_nodes);
    let (rp_enc, _rp_size) = abi_encode_bytes_field(receipt_path);

    let head_size: usize = 5 * 32;
    let bh_off: usize = head_size;
    let rr_off: usize = bh_off + bh_size;
    let pn_off: usize = rr_off + rr_size;
    let rp_off: usize = pn_off + pn_size;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&selector);
    out.extend_from_slice(&U256::from(0x40u64).to_be_bytes::<32>());
    out.extend_from_slice(&target_block_number.to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(bh_off).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(rr_off).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(pn_off).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(rp_off).to_be_bytes::<32>());
    out.extend_from_slice(&log_index.to_be_bytes::<32>());
    out.extend_from_slice(&bh_enc);
    out.extend_from_slice(&rr_enc);
    out.extend_from_slice(&pn_enc);
    out.extend_from_slice(&rp_enc);

    Bytes::from(out)
}

#[allow(dead_code)]
#[derive(Debug)]
enum FlowOutcome {
    Success {
        gas_used: u64,
    },
    BondRevert {
        selector: Option<u32>,
        gas_used: u64,
    },
    BondHalt {
        reason: String,
        gas_used: u64,
    },
    CollectRevert {
        selector: Option<u32>,
        gas_used: u64,
    },
    CollectHalt {
        reason: String,
        gas_used: u64,
    },
}

fn revert_selector(output: &[u8]) -> Option<u32> {
    if output.len() >= 4 {
        Some(u32::from_be_bytes([
            output[0], output[1], output[2], output[3],
        ]))
    } else {
        None
    }
}

fn execute_collect_proof_flow(
    deployment_bytecode: Bytes,
    bond_calldata: Bytes,
    collect_selector: [u8; 4],
    label: &str,
) -> Result<FlowOutcome> {
    let deployer = Address::from([0x42u8; 20]);
    let executor = PROOF_EXECUTOR;

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
    db.insert_account_info(
        executor,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );
    db.insert_account_info(
        PROOF_TOKEN,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(mock_token_bytecode())),
        },
    );
    db.cache
        .block_hashes
        .insert(U256::from(TARGET_BLOCK_NUMBER), TARGET_BLOCK_HASH);

    let block_env = BlockEnv {
        number: U256::from(TARGET_BLOCK_NUMBER + 10),
        ..Default::default()
    };
    let mut evm = Context::mainnet()
        .with_db(db)
        .with_block(block_env)
        .build_mainnet_with_inspector(RingTracer);

    println!("\n=== [{}] Deploying escrow ===", label);
    println!("  deployment_bytecode: {} bytes", deployment_bytecode.len());

    let deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: deployment_bytecode,
        value: U256::ZERO,
        nonce: 0,
        ..Default::default()
    };
    let deploy_result = evm
        .transact(deploy_tx)
        .map_err(|e| eyre!("Deploy tx failed: {:?}", e))?;
    evm.db_mut().commit(deploy_result.state.clone());

    let contract_address = match deploy_result.result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(addr)),
            gas_used,
            ..
        } => {
            println!("✓ [{}] deployed at {} (gas: {})", label, addr, gas_used);
            if let Ok(dir) = std::env::var("DUMP_OBFUSCATED") {
                if let Some(account) = evm.db().cache.accounts.get(&addr) {
                    if let Some(code) = &account.info.code {
                        let bytes = match code {
                            revm::bytecode::Bytecode::LegacyAnalyzed(analyzed) => {
                                analyzed.bytecode().clone()
                            }
                            other => Bytes::copy_from_slice(other.original_byte_slice()),
                        };
                        let path = format!("{dir}/{label}.runtime.hex");
                        let _ = std::fs::write(&path, hex::encode(&bytes));
                        println!("✓ [{}] dumped runtime code to {}", label, path);
                    }
                }
            }
            addr
        }
        ExecutionResult::Success { .. } => {
            return Err(eyre!("Deploy succeeded without a contract address"));
        }
        ExecutionResult::Revert { output, gas_used } => {
            return Err(eyre!(
                "Deploy REVERTED (gas: {}): 0x{}",
                gas_used,
                hex::encode(output)
            ));
        }
        ExecutionResult::Halt { reason, gas_used } => {
            return Err(eyre!("Deploy HALTED (gas: {}): {:?}", gas_used, reason));
        }
    };

    println!("\n=== [{}] Bonding as PROOF_EXECUTOR ===", label);
    let bond_tx = TxEnv {
        caller: executor,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: bond_calldata,
        value: U256::ZERO,
        nonce: 0,
        ..Default::default()
    };
    let bond_result = evm
        .transact(bond_tx)
        .map_err(|e| eyre!("Bond tx failed: {:?}", e))?;
    evm.db_mut().commit(bond_result.state.clone());

    match bond_result.result {
        ExecutionResult::Success { gas_used, .. } => {
            println!("✓ [{}] bond() succeeded (gas: {})", label, gas_used);
        }
        ExecutionResult::Revert { output, gas_used } => {
            return Ok(FlowOutcome::BondRevert {
                selector: revert_selector(&output),
                gas_used,
            });
        }
        ExecutionResult::Halt { reason, gas_used } => {
            return Ok(FlowOutcome::BondHalt {
                reason: format!("{:?}", reason),
                gas_used,
            });
        }
    }

    println!(
        "\n=== [{}] Calling collect() with real ReceiptProof ===",
        label
    );
    let block_header = hex::decode(BLOCK_HEADER_HEX)
        .map_err(|e| eyre!("Failed to decode block_header hex: {}", e))?;
    let receipt_rlp = hex::decode(RECEIPT_RLP_HEX)
        .map_err(|e| eyre!("Failed to decode receipt_rlp hex: {}", e))?;
    let proof_nodes = hex::decode(PROOF_NODES_HEX)
        .map_err(|e| eyre!("Failed to decode proof_nodes hex: {}", e))?;
    let receipt_path = hex::decode(RECEIPT_PATH_HEX)
        .map_err(|e| eyre!("Failed to decode receipt_path hex: {}", e))?;

    let collect_calldata = build_collect_calldata(
        collect_selector,
        &block_header,
        &receipt_rlp,
        &proof_nodes,
        &receipt_path,
        U256::ZERO,
        U256::from(TARGET_BLOCK_NUMBER),
    );
    println!(
        "  collect() calldata: {} bytes (selector 0x{})",
        collect_calldata.len(),
        hex::encode(collect_selector)
    );

    let collect_tx = TxEnv {
        caller: executor,
        gas_limit: 30_000_000,
        kind: TxKind::Call(contract_address),
        data: collect_calldata,
        value: U256::ZERO,
        nonce: 1,
        ..Default::default()
    };
    let trace_collect = std::env::var("TRACE_COLLECT").is_ok();
    let collect_result = if trace_collect {
        RING_BUFFER.with(|buf| buf.borrow_mut().clear());
        let result = evm.inspect(collect_tx, RingTracer);
        dump_ring_buffer(label);
        result
    } else {
        evm.transact(collect_tx)
    }
    .map_err(|e| eyre!("Collect tx failed: {:?}", e))?;

    match collect_result.result {
        ExecutionResult::Success { gas_used, .. } => {
            println!("✓ [{}] collect() SUCCEEDED (gas: {})", label, gas_used);
            Ok(FlowOutcome::Success { gas_used })
        }
        ExecutionResult::Revert { output, gas_used } => Ok(FlowOutcome::CollectRevert {
            selector: revert_selector(&output),
            gas_used,
        }),
        ExecutionResult::Halt { reason, gas_used } => Ok(FlowOutcome::CollectHalt {
            reason: format!("{:?}", reason),
            gas_used,
        }),
    }
}

async fn build_obfuscated_flow_inputs(
    label: &str,
    transforms: Vec<Box<dyn Transform>>,
) -> Result<(Bytes, Bytes, [u8; 4])> {
    println!("\n=== Obfuscating escrow bytecode for {} ===", label);
    let seed = Seed::from_hex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .expect("valid fixed seed");
    let config = ObfuscationConfig {
        seed,
        transforms,
        preserve_unknown_opcodes: true,
    };
    let obfuscation_result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate bytecode for {}: {:?}", label, e))?;

    let selector_mapping = obfuscation_result
        .selector_mapping
        .as_ref()
        .ok_or_else(|| eyre!("No selector mapping in obfuscation result"))?;
    let mappings = EscrowMappings::from_obfuscator_output(selector_mapping)
        .map_err(|e| eyre!("Failed to build EscrowMappings for {}: {}", label, e))?;
    let caller = ObfuscatedCaller::new(mappings);
    println!(
        "✓ [{}] built EscrowMappings with {} selectors",
        label,
        selector_mapping.len()
    );

    // Optional: dump obfuscated bytecode hex for offline disassembly/debug.
    if let Ok(dir) = std::env::var("DUMP_OBFUSCATED") {
        let path = format!("{dir}/{label}.hex");
        let body = obfuscation_result
            .obfuscated_bytecode
            .trim_start_matches("0x");
        let _ = std::fs::write(&path, body);
        println!("✓ [{}] dumped obfuscated bytecode to {}", label, path);
    }

    let deployment_bytecode = prepare_bytecode_with_args(
        &obfuscation_result.obfuscated_bytecode,
        PROOF_TOKEN,
        PROOF_RECIPIENT,
        U256::from(TRANSFER_AMOUNT),
        U256::from(REWARD_AMOUNT),
        U256::from(PAYMENT_AMOUNT),
    )?;
    let bond_calldata = caller.bond_call_data(U256::from(BOND_AMOUNT));
    let collect_selector: [u8; 4] =
        caller
            .collect_call_data()
            .as_ref()
            .try_into()
            .map_err(|_| {
                eyre!(
                    "collect_call_data() did not return exactly 4 bytes for {}",
                    label
                )
            })?;

    Ok((deployment_bytecode, bond_calldata, collect_selector))
}

fn assert_collect_flow_success(label: &str, outcome: FlowOutcome) -> Result<()> {
    match outcome {
        FlowOutcome::Success { gas_used } => {
            println!(
                "✓ [{}] collect() succeeded end-to-end (gas: {})",
                label, gas_used
            );
            Ok(())
        }
        FlowOutcome::BondRevert { selector, gas_used } => Err(eyre!(
            "[{}] bond() reverted (gas: {}, selector: {})",
            label,
            gas_used,
            selector
                .map(|s| format!("0x{s:08x}"))
                .unwrap_or_else(|| "(empty)".to_string())
        )),
        FlowOutcome::BondHalt { reason, gas_used } => Err(eyre!(
            "[{}] bond() halted (gas: {}): {}",
            label,
            gas_used,
            reason
        )),
        FlowOutcome::CollectRevert { selector, gas_used } => Err(eyre!(
            "[{}] collect() reverted (gas: {}, selector: {})",
            label,
            gas_used,
            selector
                .map(|s| format!("0x{s:08x}"))
                .unwrap_or_else(|| "(empty)".to_string())
        )),
        FlowOutcome::CollectHalt { reason, gas_used } => Err(eyre!(
            "[{}] collect() halted (gas: {}): {}",
            label,
            gas_used,
            reason
        )),
    }
}

#[tokio::test]
async fn test_collect_with_erc20_proof_baseline_succeeds() -> Result<()> {
    let deployment_bytecode = prepare_bytecode_with_args(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        PROOF_TOKEN,
        PROOF_RECIPIENT,
        U256::from(TRANSFER_AMOUNT),
        U256::from(REWARD_AMOUNT),
        U256::from(PAYMENT_AMOUNT),
    )?;
    let bond_args = U256::from(BOND_AMOUNT).to_be_bytes::<32>();
    let bond_calldata = build_standard_calldata(ESCROW_BOND, &bond_args);
    let outcome = execute_collect_proof_flow(
        deployment_bytecode,
        bond_calldata,
        ESCROW_COLLECT.0,
        "baseline",
    )?;

    match outcome {
        FlowOutcome::Success { gas_used } => {
            println!(
                "✓ baseline collect() succeeded end-to-end (gas: {})",
                gas_used
            );
            Ok(())
        }
        other => Err(eyre!(
            "baseline proof flow unexpectedly failed: {:?}",
            other
        )),
    }
}

#[tokio::test]
async fn test_collect_with_erc20_proof_dispatcher_only_succeeds() -> Result<()> {
    let label = "dispatcher_only";
    let (deployment_bytecode, bond_calldata, collect_selector) =
        build_obfuscated_flow_inputs(label, vec![]).await?;
    let outcome =
        execute_collect_proof_flow(deployment_bytecode, bond_calldata, collect_selector, label)?;
    assert_collect_flow_success(label, outcome)
}

// todo(g4titanx): create bugs.md and update bug findings, cause and fix, for posterity

/// Regression probe for three distinct bugs in ArithmeticChain that all
/// manifested as `collect()` reverting with `WrongEventSignature()`
/// (selector `0x49b4a8ba`) on the ERC20 `Transfer` event topic check:
///
/// 1. `scatter.rs::generate_load_instructions` was pushing the CODECOPY
///    arguments in the wrong stack order. EVM CODECOPY pops `destOffset`
///    from the top, then `offset`, then `size`, but the generator emitted
///    them as `PUSH destOffset; PUSH offset; PUSH size; CODECOPY`, leaving
///    `size` on top. The EVM then interpreted `size` (`0x20`) as
///    `destOffset` and `destOffset` (`0x00`) as `size`, performing a
///    zero-byte copy. The subsequent `MLOAD` always returned
///    zero-initialised memory, so the chain's first OR reduction
///    collapsed to `V0 | 0 = V0` and the final value diverged from the
///    backward-computed target.
///
/// 2. `CfgIrBundle::patch_arithmetic_chain_codecopy_offsets` did not
///    exist. AC recorded its `runtime_length` estimate at Step 3 transform
///    time, then Step 5's dispatcher reapply passes
///    (`reapply_stub_patches`, `reapply_decoy_patches`,
///    `reapply_controller_patches`) widened some PUSHes post-`reindex_pcs`
///    and grew the runtime past the estimate. AC's CODECOPY offsets still
///    referenced the old estimate, so they pointed into live runtime code
///    instead of the appended data section — the chain loaded random
///    bytecode bytes as `V1`.
///
/// 3. The post-reindex patch needed the right pattern after fix (1).
///    With the corrected `PUSH size; PUSH offset; PUSH destOffset;
///    CODECOPY` ordering, the offset PUSH moved one slot forward in the
///    instruction window; the scanner was updated to match the new
///    shape and capped with `old_value >= estimate` to avoid touching
///    coincidental `PUSH1 0x20; PUSH<n>; PUSH1 0x00; CODECOPY` sequences
///    the Solidity compiler emits for unrelated code copies.
#[tokio::test]
async fn test_collect_with_erc20_proof_dispatcher_plus_arithmetic_chain_succeeds() -> Result<()> {
    let label = "dispatcher_plus_arithmetic_chain";
    let (deployment_bytecode, bond_calldata, collect_selector) =
        build_obfuscated_flow_inputs(label, vec![Box::new(ArithmeticChain::new())]).await?;
    let outcome =
        execute_collect_proof_flow(deployment_bytecode, bond_calldata, collect_selector, label)?;
    assert_collect_flow_success(label, outcome)
}

/// Regression probe for two PushSplit bugs that both made `collect()`
/// halt with `InvalidJump` at the 30M gas limit:
///
/// 1. `push_split.rs` emitted the split chain as `PUSH p1; op; PUSH p2;
///    op; ...`, where the first `op` consumed whatever value the
///    preceding code had left on the stack. The generator expected the
///    chain to start from the identity element (0 for ADD/XOR), but the
///    replaced PUSH was a pure stack push — so the produced constant was
///    `(prev_top) ⊕ p1 ⊕ ... ⊕ pn` instead of `p1 ⊕ ... ⊕ pn`, silently
///    corrupting the literal (in this fixture, the error-selector
///    constant fed into the `revert CustomError()` emit sequence). Fix
///    was to prepend a `PUSH0` before the chain so the first op always
///    starts from zero.
///
/// 2. `cfg_ir::remap_orphan_jump_pushes` only scanned blocks ending with
///    `JUMP`/`JUMPI`. Solidity's inherited-function-call convention
///    (EscrowERC20 → EscrowBase) pushes the return address in one block
///    and consumes it from a `JUMP` in a later block, with a `JUMPDEST`
///    separating them. After PushSplit grew some blocks, those return
///    addresses were stale but invisible to the extended scan. The fix
///    drops the JUMP-ending filter and walks every body block, scoped to
///    `PUSH2+` to avoid false positives on small literals that coincide
///    with early `JUMPDEST` PCs. This test caught it as a runtime JUMP
///    at PC `0x07be` consuming a stale PUSH2 from `0x07a6`.
#[tokio::test]
async fn test_collect_with_erc20_proof_dispatcher_plus_push_split_succeeds() -> Result<()> {
    let label = "dispatcher_plus_push_split";
    let (deployment_bytecode, bond_calldata, collect_selector) =
        build_obfuscated_flow_inputs(label, vec![Box::new(PushSplit::new())]).await?;
    let outcome =
        execute_collect_proof_flow(deployment_bytecode, bond_calldata, collect_selector, label)?;
    assert_collect_flow_success(label, outcome)
}

/// Regression probe for two SlotShuffle bugs that made `bond()` revert
/// with `NotFunded()` (selector `0xd5ef09ba`) — i.e. the `funded = true`
/// SSTORE and the runtime `!funded` SLOAD disagreed on which slot
/// `funded` lived in:
///
/// 1. SlotShuffle's collection and rewrite passes used `parse_slot_candidate`,
///    which only recognised adjacent `PUSH <slot>; SLOAD/SSTORE`. Solidity's
///    read-modify-write of a packed bool field emits a `PUSH <slot>; DUP1;
///    SLOAD; ...; SSTORE` pattern that shares the slot via the DUP — the
///    PUSH itself was never adjacent to the access, so it never made it
///    into the shuffle mapping and never got rewritten. The fix replaces
///    the adjacency check with a trace-based scan that runs backward from
///    every SLOAD/SSTORE via DUP/SWAP/arithmetic to find the source PUSH,
///    and records per-block `(push_idx, width, slot_bytes)` so the
///    rewrite phase patches exactly the PUSHes the collection phase saw.
///
/// 2. The CFG only contains runtime-section blocks, but Solidity inlines
///    the constructor's invocation of `fund()` into the **init section**,
///    which is never seen by any transform. The init-code
///    `PUSH1 0x07; SSTORE` that sets `funded = true` would still write to
///    original slot `7`, while the runtime `PUSH1 0x07; SLOAD` got
///    remapped to some other slot — the two sections disagreed and
///    `bond()` read zero. Fix: `slot_shuffle.rs::init_literal_slots`
///    walks the raw init-section bytes, finds every `PUSH; SLOAD/SSTORE`
///    pair, and excludes those slot literals from the shuffle mapping so
///    init-touched slots stay at their original indices.
#[tokio::test]
async fn test_collect_with_erc20_proof_dispatcher_plus_slot_shuffle_succeeds() -> Result<()> {
    let label = "dispatcher_plus_slot_shuffle";
    let (deployment_bytecode, bond_calldata, collect_selector) =
        build_obfuscated_flow_inputs(label, vec![Box::new(SlotShuffle::new())]).await?;
    let outcome =
        execute_collect_proof_flow(deployment_bytecode, bond_calldata, collect_selector, label)?;
    assert_collect_flow_success(label, outcome)
}

#[tokio::test]
async fn test_collect_with_erc20_proof_dispatcher_plus_string_obfuscate_succeeds() -> Result<()> {
    let label = "dispatcher_plus_string_obfuscate";
    let (deployment_bytecode, bond_calldata, collect_selector) =
        build_obfuscated_flow_inputs(label, vec![Box::new(StringObfuscate::new())]).await?;
    let outcome =
        execute_collect_proof_flow(deployment_bytecode, bond_calldata, collect_selector, label)?;
    assert_collect_flow_success(label, outcome)
}

#[tokio::test]
async fn test_collect_with_erc20_proof_default_pipeline_succeeds() -> Result<()> {
    let label = "default_pipeline";
    let (deployment_bytecode, bond_calldata, collect_selector) = build_obfuscated_flow_inputs(
        label,
        vec![
            Box::new(ArithmeticChain::new()),
            Box::new(PushSplit::new()),
            Box::new(SlotShuffle::new()),
            Box::new(StringObfuscate::new()),
        ],
    )
    .await?;
    let outcome =
        execute_collect_proof_flow(deployment_bytecode, bond_calldata, collect_selector, label)?;
    assert_collect_flow_success(label, outcome)
}
