use crate::e2e::{ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, ESCROW_CONTRACT_RUNTIME_BYTECODE};
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::arithmetic_chain::ArithmeticChain;
use azoth_transform::push_split::PushSplit;
use azoth_transform::slot_shuffle::SlotShuffle;
use azoth_transform::string_obfuscate::StringObfuscate;
use azoth_transform::Transform;

const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn cfg_instruction_snapshot(
    cfg_ir: &azoth_core::cfg_ir::CfgIrBundle,
) -> Vec<(usize, String, Option<String>)> {
    let mut snapshot = Vec::new();

    for node in cfg_ir.cfg.node_indices() {
        if let azoth_core::cfg_ir::Block::Body(body) = &cfg_ir.cfg[node] {
            for instr in &body.instructions {
                snapshot.push((instr.pc, format!("{:?}", instr.op), instr.imm.clone()));
            }
        }
    }

    snapshot
}

async fn assert_transform_deterministic_for_bytecode(
    bytecode_name: &str,
    bytecode: &str,
    transform_name: &str,
    make_transform: fn() -> Box<dyn Transform>,
) {
    let seed = Seed::from_hex(FIXED_SEED).unwrap();
    let (mut cfg_a, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();
    let (mut cfg_b, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    let mut rng_a = seed.create_deterministic_rng();
    let mut rng_b = seed.create_deterministic_rng();
    let transform_a = make_transform();
    let transform_b = make_transform();

    let changed_a = transform_a.apply(&mut cfg_a, &mut rng_a).unwrap();
    let changed_b = transform_b.apply(&mut cfg_b, &mut rng_b).unwrap();
    let snapshot_a = cfg_instruction_snapshot(&cfg_a);
    let snapshot_b = cfg_instruction_snapshot(&cfg_b);

    assert_eq!(
        changed_a, changed_b,
        "{transform_name} should report the same changed flag for the same seed on {bytecode_name}"
    );
    assert_eq!(
        snapshot_a, snapshot_b,
        "{transform_name} should produce an identical instruction stream for the same seed on {bytecode_name}"
    );
}

#[tokio::test]
async fn arithmetic_chain_is_deterministic_for_same_seed() {
    assert_transform_deterministic_for_bytecode(
        "escrow runtime",
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        "ArithmeticChain",
        || Box::new(ArithmeticChain::new()),
    )
    .await;
    assert_transform_deterministic_for_bytecode(
        "escrow deployment",
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        "ArithmeticChain",
        || Box::new(ArithmeticChain::new()),
    )
    .await;
}

#[tokio::test]
async fn push_split_is_deterministic_for_same_seed() {
    assert_transform_deterministic_for_bytecode(
        "escrow runtime",
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        "PushSplit",
        || Box::new(PushSplit::new()),
    )
    .await;
    assert_transform_deterministic_for_bytecode(
        "escrow deployment",
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        "PushSplit",
        || Box::new(PushSplit::new()),
    )
    .await;
}

#[tokio::test]
async fn slot_shuffle_is_deterministic_for_same_seed() {
    assert_transform_deterministic_for_bytecode(
        "escrow runtime",
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        "SlotShuffle",
        || Box::new(SlotShuffle::new()),
    )
    .await;
    assert_transform_deterministic_for_bytecode(
        "escrow deployment",
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        "SlotShuffle",
        || Box::new(SlotShuffle::new()),
    )
    .await;
}

#[tokio::test]
async fn string_obfuscate_is_deterministic_for_same_seed() {
    assert_transform_deterministic_for_bytecode(
        "escrow runtime",
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        "StringObfuscate",
        || Box::new(StringObfuscate::new()),
    )
    .await;
    assert_transform_deterministic_for_bytecode(
        "escrow deployment",
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        "StringObfuscate",
        || Box::new(StringObfuscate::new()),
    )
    .await;
}
