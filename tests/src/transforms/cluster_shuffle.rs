use azoth_core::{
    cfg_ir::CfgIrBundle,
    detection::SectionKind,
    process_bytecode_to_cfg,
    seed::{DeterministicRng, Seed},
};
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::Transform;

const STACK_CARRIED_JUMPI: &str = "0x6009600090575f5ff35b5f5ffd";

// This is structurally valid compiler CBOR and begins on an instruction boundary, but execution
// still falls through into it. LOG2 consumes four zeroes, the `solc` pair becomes a PUSH5 plus a
// PC/MSTORE/RETURN program, and a valid IPFS pair remains later in the same map. Detection is not
// proof that an auxdata-classified suffix is unreachable or safe to rewrite.
const EXECUTABLE_AUXDATA_LOOKALIKE: &str = concat!(
    "0x5f5f5f5f",                         // stack inputs for the suffix's LOG2
    "a264736f6c634a585f5260205ff3000000", // solc pair with executable value bytes
    "646970667358221220",                 // IPFS key, 34-byte value, and multihash prefix
    "1111111111111111111111111111111111111111111111111111111111111111",
    "003a", // length marker: 58-byte CBOR payload
);
const MOVABLE_PREFIX: &str = "0x6007565b005b005b";
const MOVABLE_PREFIX_WITH_LIVE_PC_SUFFIX: &str = concat!(
    "0x6007565b005b005b5f5f5f", // movable blocks, then JUMPDEST and LOG1 inputs
    "a164736f6c634a585f5260205ff3000000", // valid CBOR; PC executes at runtime
    "0011",                     // length marker: 17-byte CBOR payload
);
const STATIC_JUMP_INTO_DETECTED_SUFFIX: &str = "0x600d565b0000a164736f6c63435b0000000a";
const DUAL_USE_JUMPI_POINTER: &str = "0x600c805f90575f5260205ff35b005b00";

struct CorruptDetectedSuffix;
struct CorruptInitSection;

impl Transform for CorruptDetectedSuffix {
    fn name(&self) -> &'static str {
        "CorruptDetectedSuffix"
    }

    fn apply(
        &self,
        ir: &mut CfgIrBundle,
        _rng: &mut DeterministicRng,
    ) -> azoth_transform::Result<bool> {
        let suffix = ir
            .clean_report
            .removed
            .iter_mut()
            .find(|removed| removed.kind == SectionKind::Auxdata)
            .expect("fixture must contain detected auxdata");
        let mut bytes = suffix.data.to_vec();
        bytes[10] ^= 0xff;
        suffix.data = bytes.into();
        Ok(true)
    }
}

impl Transform for CorruptInitSection {
    fn name(&self) -> &'static str {
        "CorruptInitSection"
    }

    fn apply(
        &self,
        ir: &mut CfgIrBundle,
        _rng: &mut DeterministicRng,
    ) -> azoth_transform::Result<bool> {
        let init = ir
            .clean_report
            .removed
            .iter_mut()
            .find(|removed| removed.kind == SectionKind::Init)
            .expect("fixture must contain init code");
        let mut bytes = init.data.to_vec();
        bytes[0] ^= 0x01;
        init.data = bytes.into();
        Ok(true)
    }
}

fn push32_split_reproducer() -> String {
    let mut bytes = vec![0x7f];
    bytes.extend_from_slice(&[0u8; 29]);
    bytes.extend_from_slice(&[0x55, 0x00, 0x01]);
    assert_eq!(bytes.len(), 33);
    format!("0x{}", hex::encode(bytes))
}

fn execution_succeeds(runtime_hex: &str) -> bool {
    use revm::bytecode::Bytecode;
    use revm::context::result::ExecutionResult;
    use revm::context::TxEnv;
    use revm::database::InMemoryDB;
    use revm::primitives::{Address, Bytes, TxKind, U256};
    use revm::state::AccountInfo;
    use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

    let runtime = hex::decode(runtime_hex.trim_start_matches("0x")).expect("runtime hex");
    let contract = Address::from([0x11; 20]);
    let caller = Address::from([0x22; 20]);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        contract,
        AccountInfo {
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(Bytes::from(runtime))),
            balance: U256::ZERO,
        },
    );
    db.insert_account_info(
        caller,
        AccountInfo {
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
            balance: U256::from(1_000_000u64),
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let result = evm
        .transact(TxEnv {
            caller,
            gas_limit: 1_000_000,
            kind: TxKind::Call(contract),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .expect("execute runtime");

    matches!(result.result, ExecutionResult::Success { .. })
}

fn execution_output(runtime_hex: &str) -> Vec<u8> {
    use revm::bytecode::Bytecode;
    use revm::context::result::{ExecutionResult, Output};
    use revm::context::TxEnv;
    use revm::database::InMemoryDB;
    use revm::primitives::{Address, Bytes, TxKind, U256};
    use revm::state::AccountInfo;
    use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

    let runtime = hex::decode(runtime_hex.trim_start_matches("0x")).expect("runtime hex");
    let contract = Address::from([0x11; 20]);
    let caller = Address::from([0x22; 20]);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        contract,
        AccountInfo {
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(Bytes::from(runtime))),
            balance: U256::ZERO,
        },
    );
    db.insert_account_info(
        caller,
        AccountInfo {
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
            balance: U256::from(1_000_000u64),
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let result = evm
        .transact(TxEnv {
            caller,
            gas_limit: 1_000_000,
            kind: TxKind::Call(contract),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .expect("execute runtime");

    match result.result {
        ExecutionResult::Success {
            output: Output::Call(bytes),
            ..
        } => bytes.to_vec(),
        other => panic!("runtime did not return successfully: {other:?}"),
    }
}

#[tokio::test]
async fn safe_pipeline_preserves_stack_carried_jumpi_false_path() {
    assert!(execution_succeeds(STACK_CARRIED_JUMPI));

    let result = obfuscate_bytecode(
        STACK_CARRIED_JUMPI,
        STACK_CARRIED_JUMPI,
        ObfuscationConfig::with_seed(Seed::from_bytes([0; 32])),
    )
    .await
    .expect("safe profile must accept the resolved dynamic JUMPI");

    assert_eq!(result.obfuscated_runtime, STACK_CARRIED_JUMPI);
    assert!(execution_succeeds(&result.obfuscated_runtime));
    assert!(!result
        .metadata
        .transforms_applied
        .iter()
        .any(|name| name == "ClusterShuffle"));
}

#[tokio::test]
async fn safe_pipeline_preserves_executable_auxdata_lookalike_byte_for_byte() {
    let (_, _, sections, _) = process_bytecode_to_cfg(
        EXECUTABLE_AUXDATA_LOOKALIKE,
        false,
        EXECUTABLE_AUXDATA_LOOKALIKE,
        false,
    )
    .await
    .expect("the fixture must pass the production section detector");
    let detected_suffix = sections
        .iter()
        .find(|section| section.kind == SectionKind::Auxdata)
        .expect("length marker must classify the executable tail as auxdata");
    assert_eq!((detected_suffix.offset, detected_suffix.len), (4, 60));

    let original_output = execution_output(EXECUTABLE_AUXDATA_LOOKALIKE);
    assert_eq!(original_output.len(), 32);
    assert_eq!(original_output[31], 11);

    let result = obfuscate_bytecode(
        EXECUTABLE_AUXDATA_LOOKALIKE,
        EXECUTABLE_AUXDATA_LOOKALIKE,
        ObfuscationConfig::with_seed(Seed::from_bytes([0x42; 32])),
    )
    .await
    .expect("the safe profile may preserve a metadata-like executable suffix");

    assert_eq!(result.obfuscated_runtime, EXECUTABLE_AUXDATA_LOOKALIKE);
    assert_eq!(result.obfuscated_bytecode, EXECUTABLE_AUXDATA_LOOKALIKE);
    assert_eq!(
        execution_output(&result.obfuscated_runtime),
        original_output
    );
    assert!(!result
        .metadata
        .transforms_applied
        .iter()
        .any(|name| name == "SolidityMetadata"));
}

#[tokio::test]
async fn finalizer_rejects_any_pass_that_mutates_a_detected_suffix() {
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x43; 32]));
    config.transforms.push(Box::new(CorruptDetectedSuffix));

    let error = obfuscate_bytecode(
        EXECUTABLE_AUXDATA_LOOKALIKE,
        EXECUTABLE_AUXDATA_LOOKALIKE,
        config,
    )
    .await
    .expect_err("a pass must never be able to commit a detected-suffix mutation");
    assert!(
        error
            .message
            .contains("attempted to mutate protected init, constructor, or compiler-suffix"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn commit_gate_rejects_transform_mutation_of_init_reconstruction_state() {
    let runtime = MOVABLE_PREFIX;
    let deployment = format!("0x6008600a5f3960085ff3{}", &runtime[2..]);
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x35; 32]));
    config.transforms.clear();
    config.transforms.push(Box::new(CorruptInitSection));

    let error = obfuscate_bytecode(&deployment, runtime, config)
        .await
        .expect_err("a transform must not mutate init bytes through the reconstruction report");
    assert!(
        error
            .message
            .contains("attempted to mutate protected init, constructor, or compiler-suffix"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn init_gas_fallback_is_exact_identity_even_when_constructor_masking_is_requested() {
    let runtime = MOVABLE_PREFIX;
    let mut deployment = format!("0x5a506008600c5f3960085ff3{}", &runtime[2..]);
    deployment.push_str(&"11".repeat(32));
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x36; 32]));
    config.obfuscate_constructor_arguments = true;

    let result = obfuscate_bytecode(&deployment, runtime, config)
        .await
        .expect("init GAS must conservatively fall back to an exact identity artifact");
    assert_eq!(result.obfuscated_bytecode, deployment);
    assert_eq!(result.obfuscated_runtime, runtime);
    assert!(result.metadata.transforms_applied.is_empty());
    assert!(!result.metadata.constructor_args_obfuscated);
}

#[tokio::test]
async fn no_transform_never_splits_or_duplicates_a_push_immediate() {
    let bytecode = push32_split_reproducer();
    let (_, _, sections, _) = process_bytecode_to_cfg(&bytecode, false, &bytecode, false)
        .await
        .expect("a length-like PUSH32 immediate must remain complete runtime code");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].kind, SectionKind::Runtime);
    assert_eq!((sections[0].offset, sections[0].len), (0, 33));

    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x44; 32]));
    config.transforms.clear();
    let result = obfuscate_bytecode(&bytecode, &bytecode, config)
        .await
        .expect("a no-transform run must preserve the exact instruction span");

    assert_eq!(result.obfuscated_runtime, bytecode);
    assert_eq!(result.obfuscated_bytecode, bytecode);
    assert_eq!(result.obfuscated_size, 33);
    assert!(result.metadata.transforms_applied.is_empty());
}

#[tokio::test]
async fn safe_pipeline_refuses_layout_change_when_detected_suffix_is_live_code() {
    let seed = Seed::from_bytes([0x24; 32]);
    let movable = obfuscate_bytecode(
        MOVABLE_PREFIX,
        MOVABLE_PREFIX,
        ObfuscationConfig::with_seed(seed.clone()),
    )
    .await
    .expect("the control-flow prefix must be independently movable");
    assert!(movable
        .metadata
        .transforms_applied
        .iter()
        .any(|name| name == "ClusterShuffle"));

    let original_output = execution_output(MOVABLE_PREFIX_WITH_LIVE_PC_SUFFIX);
    assert_eq!(original_output, [vec![0; 31], vec![18]].concat());

    let error = obfuscate_bytecode(
        MOVABLE_PREFIX_WITH_LIVE_PC_SUFFIX,
        MOVABLE_PREFIX_WITH_LIVE_PC_SUFFIX,
        ObfuscationConfig::with_seed(seed),
    )
    .await
    .expect_err("layout changes must not cross an executable metadata-like boundary");
    assert!(
        error
            .message
            .contains("retained runtime falls through into detected auxdata or padding"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn jump_into_detected_suffix_is_recorded_as_unresolved_and_refused() {
    let (bundle, _, sections, _) = process_bytecode_to_cfg(
        STATIC_JUMP_INTO_DETECTED_SUFFIX,
        false,
        STATIC_JUMP_INTO_DETECTED_SUFFIX,
        false,
    )
    .await
    .expect("direct-target fixture must build");
    let detected_suffix = sections
        .iter()
        .find(|section| section.kind == SectionKind::Auxdata)
        .expect("fixture tail must be detected as auxdata");
    assert_eq!((detected_suffix.offset, detected_suffix.len), (6, 12));
    assert!(!bundle.relationships().unresolved_control.is_empty());
    assert!(execution_succeeds(STATIC_JUMP_INTO_DETECTED_SUFFIX));

    let error = obfuscate_bytecode(
        STATIC_JUMP_INTO_DETECTED_SUFFIX,
        STATIC_JUMP_INTO_DETECTED_SUFFIX,
        ObfuscationConfig::with_seed(Seed::from_bytes([0x55; 32])),
    )
    .await
    .expect_err("a jump target outside the retained runtime must produce no artifact");
    assert!(
        error.message.contains("invalid jump target"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn safe_pipeline_refuses_dual_use_pointer_on_dynamic_jumpi_false_path() {
    assert!(execution_succeeds(DUAL_USE_JUMPI_POINTER));

    let error = obfuscate_bytecode(
        DUAL_USE_JUMPI_POINTER,
        DUAL_USE_JUMPI_POINTER,
        ObfuscationConfig::with_seed(Seed::from_bytes([0; 32])),
    )
    .await
    .expect_err("the production profile must reject a code pointer also observed as data");

    assert!(error.message.contains("runtime observes code position"));
}
