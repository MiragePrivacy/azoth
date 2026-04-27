use super::{
    deploy_contract, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, ESCROW_CONTRACT_RUNTIME_BYTECODE,
};
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::arithmetic_chain::ArithmeticChain;
use azoth_transform::cluster_shuffle::ClusterShuffle;
use azoth_transform::constant_mask::ConstantMask;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::push_split::PushSplit;
use azoth_transform::slot_shuffle::SlotShuffle;
use azoth_transform::string_obfuscate::StringObfuscate;
use azoth_transform::Transform;
use color_eyre::Result;

const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn runtime_preview_hex(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(16);
    format!("0x{}", hex::encode(&bytes[..preview_len]))
}

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
async fn test_same_seed_produces_same_deployed_runtime() -> Result<()> {
    let seed = Seed::from_hex(FIXED_SEED).unwrap();

    let result_a = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        ObfuscationConfig::with_seed(seed.clone()),
    )
    .await?;
    let result_b = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        ObfuscationConfig::with_seed(seed),
    )
    .await?;

    let deployed_a = deploy_contract(&result_a.obfuscated_bytecode)?;
    let deployed_b = deploy_contract(&result_b.obfuscated_bytecode)?;

    println!(
        "run A deployed runtime: {} bytes, prefix {}",
        deployed_a.runtime.len(),
        runtime_preview_hex(&deployed_a.runtime)
    );
    println!(
        "run B deployed runtime: {} bytes, prefix {}",
        deployed_b.runtime.len(),
        runtime_preview_hex(&deployed_b.runtime)
    );

    assert_eq!(
        result_a.obfuscated_bytecode, result_b.obfuscated_bytecode,
        "same seed should produce identical obfuscated deployment bytecode"
    );
    assert_eq!(
        result_a.obfuscated_runtime, result_b.obfuscated_runtime,
        "same seed should produce identical obfuscated runtime template"
    );
    assert_eq!(
        deployed_a.runtime, deployed_b.runtime,
        "same seed and same constructor args should produce identical deployed runtime"
    );

    Ok(())
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

#[tokio::test]
async fn constant_mask_is_deterministic_for_same_seed() {
    assert_transform_deterministic_for_bytecode(
        "escrow runtime",
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        "ConstantMask",
        || Box::new(ConstantMask::new()),
    )
    .await;
    assert_transform_deterministic_for_bytecode(
        "escrow deployment",
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        "ConstantMask",
        || Box::new(ConstantMask::new()),
    )
    .await;
}

#[tokio::test]
async fn cluster_shuffle_is_deterministic_for_same_seed() {
    assert_transform_deterministic_for_bytecode(
        "escrow runtime",
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        "ClusterShuffle",
        || Box::new(ClusterShuffle::new()),
    )
    .await;
    assert_transform_deterministic_for_bytecode(
        "escrow deployment",
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        "ClusterShuffle",
        || Box::new(ClusterShuffle::new()),
    )
    .await;
}
