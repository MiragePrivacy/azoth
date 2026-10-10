use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::context::result::{ExecutionResult, Output};
use revm::context::{ContextTr, TxEnv};
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, Log, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};
use std::collections::{BTreeMap, HashMap, HashSet};

const COUNTER_DEPLOYMENT_BYTECODE: &str =
    include_str!("../../bytecode/counter/counter_deployment.hex");
const COUNTER_RUNTIME_BYTECODE: &str = include_str!("../../bytecode/counter/counter_runtime.hex");

const SET_NUMBER_SELECTOR: u32 = 0x3fb5c1cb;
const NUMBER_SELECTOR: u32 = 0x8381f58a;
const INCREMENT_SELECTOR: u32 = 0xd09de08a;

const DEPLOY_GAS_LIMIT: u64 = 20_000_000;
const CALL_GAS_LIMIT: u64 = 5_000_000;
const MAX_INITCODE_SIZE: usize = 49_152;
const MAX_RUNTIME_SIZE: usize = 24_576;
const MAX_RELATIVE_SIZE_MULTIPLIER: usize = 2;
const INITIAL_BALANCE: u128 = 1_000_000_000_000_000_000;
const DEPLOYER: Address = Address::new([0x45; 20]);

const REGRESSION_SEEDS: [[u8; 32]; 3] = [[0x00; 32], [0x42; 32], [0xff; 32]];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CounterFunction {
    SetNumber,
    Number,
    Increment,
}

#[derive(Debug, Clone, Copy)]
struct CounterSelectors {
    set_number: [u8; 4],
    number: [u8; 4],
    increment: [u8; 4],
}

impl CounterSelectors {
    fn original() -> Self {
        Self {
            set_number: SET_NUMBER_SELECTOR.to_be_bytes(),
            number: NUMBER_SELECTOR.to_be_bytes(),
            increment: INCREMENT_SELECTOR.to_be_bytes(),
        }
    }

    fn from_mapping(mapping: &HashMap<u32, Vec<u8>>) -> Result<Self> {
        Ok(Self {
            set_number: mapped_selector(mapping, SET_NUMBER_SELECTOR)?,
            number: mapped_selector(mapping, NUMBER_SELECTOR)?,
            increment: mapped_selector(mapping, INCREMENT_SELECTOR)?,
        })
    }

    fn get(self, function: CounterFunction) -> [u8; 4] {
        match function {
            CounterFunction::SetNumber => self.set_number,
            CounterFunction::Number => self.number,
            CounterFunction::Increment => self.increment,
        }
    }

    fn all(self) -> [[u8; 4]; 3] {
        [self.set_number, self.number, self.increment]
    }
}

fn mapped_selector(mapping: &HashMap<u32, Vec<u8>>, selector: u32) -> Result<[u8; 4]> {
    let token = mapping
        .get(&selector)
        .ok_or_else(|| eyre!("missing Counter selector mapping for 0x{selector:08x}"))?;
    token.as_slice().try_into().map_err(|_| {
        eyre!(
            "Counter selector 0x{selector:08x} mapped to {} bytes instead of 4",
            token.len()
        )
    })
}

#[derive(Debug, Clone)]
enum CalldataSpec {
    Function {
        function: CounterFunction,
        arguments: Vec<u8>,
    },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeClass {
    Success,
    Revert,
    Halt,
}

#[derive(Debug, Clone)]
struct LogicalCall {
    label: &'static str,
    calldata: CalldataSpec,
    value: U256,
    expected_class: OutcomeClass,
    expected_output: Bytes,
    expected_storage: U256,
}

impl LogicalCall {
    fn encoded_calldata(&self, selectors: CounterSelectors) -> Bytes {
        match &self.calldata {
            CalldataSpec::Function {
                function,
                arguments,
            } => {
                let mut data = selectors.get(*function).to_vec();
                data.extend_from_slice(arguments);
                Bytes::from(data)
            }
            CalldataSpec::Raw(data) => Bytes::copy_from_slice(data),
        }
    }
}

fn word(value: U256) -> Vec<u8> {
    value.to_be_bytes::<32>().to_vec()
}

fn encoded_word(value: U256) -> Bytes {
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

fn arithmetic_panic_output() -> Bytes {
    let mut output = vec![0x4e, 0x48, 0x7b, 0x71];
    let mut code = [0u8; 32];
    code[31] = 0x11;
    output.extend_from_slice(&code);
    Bytes::from(output)
}

fn call_plan(unknown_selector: [u8; 4]) -> Vec<LogicalCall> {
    vec![
        LogicalCall {
            label: "number.initial",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: encoded_word(U256::ZERO),
            expected_storage: U256::ZERO,
        },
        LogicalCall {
            label: "increment.valid",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Increment,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: Bytes::new(),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "number.after_increment",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: encoded_word(U256::from(1)),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "setNumber.missing_argument",
            calldata: CalldataSpec::Function {
                function: CounterFunction::SetNumber,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Revert,
            expected_output: Bytes::new(),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "setNumber.short_argument",
            calldata: CalldataSpec::Function {
                function: CounterFunction::SetNumber,
                arguments: vec![0u8; 31],
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Revert,
            expected_output: Bytes::new(),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "dispatcher.unknown_selector",
            calldata: CalldataSpec::Raw(unknown_selector.to_vec()),
            value: U256::ZERO,
            expected_class: OutcomeClass::Revert,
            expected_output: Bytes::new(),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "dispatcher.short_calldata",
            calldata: CalldataSpec::Raw(vec![0x12, 0x34, 0x56]),
            value: U256::ZERO,
            expected_class: OutcomeClass::Revert,
            expected_output: Bytes::new(),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "number.nonpayable_value",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: Vec::new(),
            },
            value: U256::from(1),
            expected_class: OutcomeClass::Revert,
            expected_output: Bytes::new(),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "number.after_invalid_calls",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: encoded_word(U256::from(1)),
            expected_storage: U256::from(1),
        },
        LogicalCall {
            label: "setNumber.max",
            calldata: CalldataSpec::Function {
                function: CounterFunction::SetNumber,
                arguments: word(U256::MAX),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: Bytes::new(),
            expected_storage: U256::MAX,
        },
        LogicalCall {
            label: "increment.overflow",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Increment,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Revert,
            expected_output: arithmetic_panic_output(),
            expected_storage: U256::MAX,
        },
        LogicalCall {
            label: "number.after_overflow",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: encoded_word(U256::MAX),
            expected_storage: U256::MAX,
        },
        LogicalCall {
            label: "setNumber.42",
            calldata: CalldataSpec::Function {
                function: CounterFunction::SetNumber,
                arguments: word(U256::from(42)),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: Bytes::new(),
            expected_storage: U256::from(42),
        },
        LogicalCall {
            label: "number.trailing_calldata",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: vec![0xa5; 32],
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: encoded_word(U256::from(42)),
            expected_storage: U256::from(42),
        },
        LogicalCall {
            label: "increment.after_reset",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Increment,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: Bytes::new(),
            expected_storage: U256::from(43),
        },
        LogicalCall {
            label: "number.final",
            calldata: CalldataSpec::Function {
                function: CounterFunction::Number,
                arguments: Vec::new(),
            },
            value: U256::ZERO,
            expected_class: OutcomeClass::Success,
            expected_output: encoded_word(U256::from(43)),
            expected_storage: U256::from(43),
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutcomeObservation {
    class: OutcomeClass,
    output: Option<Bytes>,
    logs: Vec<Log>,
    halt_reason: Option<String>,
}

fn observe_outcome(result: &ExecutionResult) -> OutcomeObservation {
    match result {
        ExecutionResult::Success { output, logs, .. } => OutcomeObservation {
            class: OutcomeClass::Success,
            output: Some(output.data().clone()),
            logs: logs.clone(),
            halt_reason: None,
        },
        ExecutionResult::Revert { output, .. } => OutcomeObservation {
            class: OutcomeClass::Revert,
            output: Some(output.clone()),
            logs: Vec::new(),
            halt_reason: None,
        },
        ExecutionResult::Halt { reason, .. } => OutcomeObservation {
            class: OutcomeClass::Halt,
            output: None,
            logs: Vec::new(),
            halt_reason: Some(format!("{reason:?}")),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateSnapshot {
    caller_balance: U256,
    caller_nonce: u64,
    contract_balance: U256,
    contract_nonce: u64,
    contract_storage: BTreeMap<U256, U256>,
}

impl StateSnapshot {
    fn storage_value(&self, slot: U256) -> U256 {
        self.contract_storage
            .get(&slot)
            .copied()
            .unwrap_or(U256::ZERO)
    }
}

fn state_snapshot(db: &InMemoryDB, contract: Address) -> Result<StateSnapshot> {
    let caller = db
        .cache
        .accounts
        .get(&DEPLOYER)
        .ok_or_else(|| eyre!("deployer account missing from REVM state"))?;
    let contract = db
        .cache
        .accounts
        .get(&contract)
        .ok_or_else(|| eyre!("Counter account missing from REVM state"))?;

    Ok(StateSnapshot {
        caller_balance: caller.info.balance,
        caller_nonce: caller.info.nonce,
        contract_balance: contract.info.balance,
        contract_nonce: contract.info.nonce,
        contract_storage: contract
            .storage
            .iter()
            .map(|(slot, value)| (*slot, *value))
            .collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StepObservation {
    outcome: OutcomeObservation,
    state: StateSnapshot,
}

#[derive(Debug)]
struct ExecutionTranscript {
    address: Address,
    runtime_len: usize,
    deployment_logs: Vec<Log>,
    deployment_state: StateSnapshot,
    steps: Vec<StepObservation>,
}

fn execute_sequence(
    creation_bytecode: Bytes,
    selectors: CounterSelectors,
    calls: &[LogicalCall],
) -> Result<ExecutionTranscript> {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        DEPLOYER,
        AccountInfo {
            balance: U256::from(INITIAL_BALANCE),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    let deployment = evm
        .transact(TxEnv {
            caller: DEPLOYER,
            gas_limit: DEPLOY_GAS_LIMIT,
            kind: TxKind::Create,
            data: creation_bytecode,
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .map_err(|error| eyre!("Counter deployment execution failed: {error:?}"))?;

    let (address, runtime_len, deployment_logs) = match &deployment.result {
        ExecutionResult::Success {
            output: Output::Create(runtime, Some(address)),
            logs,
            ..
        } => (*address, runtime.len(), logs.clone()),
        ExecutionResult::Success { output, .. } => {
            return Err(eyre!(
                "Counter deployment returned unexpected output: {output:?}"
            ));
        }
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!(
                "Counter deployment reverted: 0x{}",
                hex::encode(output)
            ));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Counter deployment halted: {reason:?}"));
        }
    };
    evm.db_mut().commit(deployment.state);
    let deployment_state = state_snapshot(evm.db(), address)?;

    let mut steps = Vec::with_capacity(calls.len());
    for (index, call) in calls.iter().enumerate() {
        let execution = evm
            .transact(TxEnv {
                caller: DEPLOYER,
                gas_limit: CALL_GAS_LIMIT,
                kind: TxKind::Call(address),
                data: call.encoded_calldata(selectors),
                value: call.value,
                nonce: (index + 1) as u64,
                ..Default::default()
            })
            .map_err(|error| eyre!("{} execution failed: {error:?}", call.label))?;
        let outcome = observe_outcome(&execution.result);
        evm.db_mut().commit(execution.state);
        let state = state_snapshot(evm.db(), address)?;
        steps.push(StepObservation { outcome, state });
    }

    Ok(ExecutionTranscript {
        address,
        runtime_len,
        deployment_logs,
        deployment_state,
        steps,
    })
}

fn choose_unknown_selector(obfuscated: CounterSelectors) -> [u8; 4] {
    let forbidden: HashSet<[u8; 4]> = CounterSelectors::original()
        .all()
        .into_iter()
        .chain(obfuscated.all())
        .collect();
    let mut candidate = 0xdecafbad_u32;

    loop {
        let bytes = candidate.to_be_bytes();
        if !forbidden.contains(&bytes) {
            return bytes;
        }
        candidate = candidate.wrapping_add(0x9e37_79b9);
    }
}

fn assert_mapping_is_unambiguous(mapped: CounterSelectors, seed_label: &str) {
    let originals: HashSet<_> = CounterSelectors::original().all().into_iter().collect();
    let mapped_values = mapped.all();
    let unique: HashSet<_> = mapped_values.into_iter().collect();

    assert_eq!(
        unique.len(),
        mapped_values.len(),
        "mapped selectors must be unique for seed {seed_label}"
    );
    for token in mapped_values {
        assert!(
            !originals.contains(&token),
            "mapped token 0x{} aliases an original Counter selector for seed {seed_label}",
            hex::encode(token)
        );
    }
}

fn assert_original_semantics(
    transcript: &ExecutionTranscript,
    calls: &[LogicalCall],
    seed_label: &str,
) {
    assert!(
        transcript.deployment_logs.is_empty(),
        "Counter constructor unexpectedly emitted logs for seed {seed_label}"
    );
    assert_eq!(transcript.deployment_state.contract_balance, U256::ZERO);
    assert_eq!(
        transcript.deployment_state.caller_balance,
        U256::from(INITIAL_BALANCE)
    );

    for (index, (call, observed)) in calls.iter().zip(&transcript.steps).enumerate() {
        assert_eq!(
            observed.outcome.class, call.expected_class,
            "unexpected original outcome class at {} for seed {seed_label}",
            call.label
        );
        assert_eq!(
            observed.outcome.output.as_ref(),
            Some(&call.expected_output),
            "unexpected original output at {} for seed {seed_label}",
            call.label
        );
        assert!(
            observed.outcome.logs.is_empty(),
            "Counter unexpectedly emitted logs at {} for seed {seed_label}",
            call.label
        );
        assert!(
            observed.outcome.halt_reason.is_none(),
            "Counter unexpectedly halted at {} for seed {seed_label}",
            call.label
        );
        assert_eq!(
            observed.state.storage_value(U256::ZERO),
            call.expected_storage,
            "unexpected slot zero at {} for seed {seed_label}",
            call.label
        );
        assert_eq!(
            observed.state.contract_balance,
            U256::ZERO,
            "Counter retained value at {} for seed {seed_label}",
            call.label
        );
        assert_eq!(
            observed.state.caller_balance,
            U256::from(INITIAL_BALANCE),
            "deployer value effect differed at {} for seed {seed_label}",
            call.label
        );
        assert_eq!(
            observed.state.caller_nonce,
            (index + 2) as u64,
            "unexpected deployer nonce at {} for seed {seed_label}",
            call.label
        );
    }
}

fn assert_transcripts_equivalent(
    original: &ExecutionTranscript,
    obfuscated: &ExecutionTranscript,
    calls: &[LogicalCall],
    seed_label: &str,
) {
    assert_eq!(
        original.address, obfuscated.address,
        "CREATE address changed for seed {seed_label}"
    );
    assert_eq!(
        original.deployment_logs, obfuscated.deployment_logs,
        "constructor logs changed for seed {seed_label}"
    );
    assert_eq!(
        original.deployment_state, obfuscated.deployment_state,
        "constructor state/value effects changed for seed {seed_label}"
    );
    assert_eq!(original.steps.len(), obfuscated.steps.len());

    for ((call, original_step), obfuscated_step) in
        calls.iter().zip(&original.steps).zip(&obfuscated.steps)
    {
        assert_eq!(
            original_step.outcome, obfuscated_step.outcome,
            "observable execution diverged at {} for seed {seed_label}",
            call.label
        );
        assert_eq!(
            original_step.state, obfuscated_step.state,
            "post-state/value effects diverged at {} for seed {seed_label}",
            call.label
        );
    }
}

#[tokio::test]
async fn production_counter_is_differentially_equivalent_for_fixed_seed_corpus() -> Result<()> {
    let original_creation = Bytes::from(hex::decode(
        COUNTER_DEPLOYMENT_BYTECODE.trim().trim_start_matches("0x"),
    )?);
    let original_runtime = hex::decode(COUNTER_RUNTIME_BYTECODE.trim().trim_start_matches("0x"))?;
    let mut distinct_outputs = HashSet::new();

    for seed_bytes in REGRESSION_SEEDS {
        let seed_label = hex::encode(seed_bytes);
        let first = obfuscate_bytecode(
            COUNTER_DEPLOYMENT_BYTECODE,
            COUNTER_RUNTIME_BYTECODE,
            ObfuscationConfig::with_seed(Seed::from_bytes(seed_bytes)),
        )
        .await
        .map_err(|error| eyre!("obfuscation failed for seed {seed_label}: {error}"))?;
        let repeat = obfuscate_bytecode(
            COUNTER_DEPLOYMENT_BYTECODE,
            COUNTER_RUNTIME_BYTECODE,
            ObfuscationConfig::with_seed(Seed::from_bytes(seed_bytes)),
        )
        .await
        .map_err(|error| eyre!("repeat obfuscation failed for seed {seed_label}: {error}"))?;

        assert_eq!(
            first.obfuscated_bytecode, repeat.obfuscated_bytecode,
            "deployment output was nondeterministic for seed {seed_label}"
        );
        assert_eq!(
            first.obfuscated_runtime, repeat.obfuscated_runtime,
            "runtime output was nondeterministic for seed {seed_label}"
        );
        assert_eq!(
            first.selector_mapping, repeat.selector_mapping,
            "selector mapping was nondeterministic for seed {seed_label}"
        );
        assert_eq!(
            first.metadata.transforms_applied, repeat.metadata.transforms_applied,
            "applied-pass metadata was nondeterministic for seed {seed_label}"
        );
        assert_eq!(
            first.metadata.transform_outcomes, repeat.metadata.transform_outcomes,
            "pass outcomes were nondeterministic for seed {seed_label}"
        );

        let obfuscated_creation = Bytes::from(hex::decode(
            first.obfuscated_bytecode.trim_start_matches("0x"),
        )?);
        let obfuscated_runtime = hex::decode(first.obfuscated_runtime.trim_start_matches("0x"))?;
        assert_ne!(
            obfuscated_creation, original_creation,
            "production pipeline made no bytecode change for seed {seed_label}"
        );
        assert!(
            obfuscated_creation.len() <= original_creation.len() * MAX_RELATIVE_SIZE_MULTIPLIER,
            "initcode exceeded {}x relative ceiling for seed {seed_label}: {} > {}",
            MAX_RELATIVE_SIZE_MULTIPLIER,
            obfuscated_creation.len(),
            original_creation.len() * MAX_RELATIVE_SIZE_MULTIPLIER
        );
        assert!(
            obfuscated_runtime.len() <= original_runtime.len() * MAX_RELATIVE_SIZE_MULTIPLIER,
            "runtime template exceeded {}x relative ceiling for seed {seed_label}: {} > {}",
            MAX_RELATIVE_SIZE_MULTIPLIER,
            obfuscated_runtime.len(),
            original_runtime.len() * MAX_RELATIVE_SIZE_MULTIPLIER
        );
        assert!(obfuscated_creation.len() <= MAX_INITCODE_SIZE);
        assert!(obfuscated_runtime.len() <= MAX_RUNTIME_SIZE);

        let mapping = first
            .selector_mapping
            .as_ref()
            .ok_or_else(|| eyre!("missing selector mapping for seed {seed_label}"))?;
        let mapped_selectors = CounterSelectors::from_mapping(mapping)?;
        assert_mapping_is_unambiguous(mapped_selectors, &seed_label);

        let unknown_selector = choose_unknown_selector(mapped_selectors);
        let calls = call_plan(unknown_selector);
        let original_transcript = execute_sequence(
            original_creation.clone(),
            CounterSelectors::original(),
            &calls,
        )?;
        let obfuscated_transcript =
            execute_sequence(obfuscated_creation, mapped_selectors, &calls)?;

        assert_original_semantics(&original_transcript, &calls, &seed_label);
        assert_transcripts_equivalent(
            &original_transcript,
            &obfuscated_transcript,
            &calls,
            &seed_label,
        );
        assert!(
            obfuscated_transcript.runtime_len
                <= original_transcript.runtime_len * MAX_RELATIVE_SIZE_MULTIPLIER,
            "deployed runtime exceeded {}x ceiling for seed {seed_label}",
            MAX_RELATIVE_SIZE_MULTIPLIER
        );
        assert!(obfuscated_transcript.runtime_len <= MAX_RUNTIME_SIZE);
        distinct_outputs.insert(first.obfuscated_bytecode);
    }

    assert_eq!(
        distinct_outputs.len(),
        REGRESSION_SEEDS.len(),
        "fixed seed corpus should produce distinct deployment bytecode"
    );

    Ok(())
}
