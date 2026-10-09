//! Generate a reproducible labelled corpus from Azoth's current pipeline.
//!
//! This is intentionally separate from `detect_corpus`: generation requires the transform crate,
//! while the detector harness can score externally collected contracts without running Azoth.

#![recursion_limit = "256"]

use azoth_analysis::detector::CorpusSample;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{ObfuscationConfig, obfuscate_bytecode};
use revm::context::TxEnv;
use revm::context::result::{ExecutionResult, Output};
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
use std::error::Error;

const EXPECTED_PIPELINE_PROFILE: &str = "azoth-foundation-v4";

const ERC20_DEPLOYMENT: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/erc20_deployment.hex");
const ERC20_RUNTIME: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/erc20_runtime.hex");
const COUNTER_DEPLOYMENT: &str =
    include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
const COUNTER_RUNTIME: &str = include_str!("../../../tests/bytecode/counter/counter_runtime.hex");

struct Fixture {
    family: &'static str,
    deployment: &'static str,
    runtime: &'static str,
    constructor_words: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureSelection {
    All,
    EscrowErc20,
    Counter,
}

impl FixtureSelection {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "all" => Ok(Self::All),
            "escrow-erc20" => Ok(Self::EscrowErc20),
            "counter" => Ok(Self::Counter),
            _ => Err(format!(
                "fixture filter must be `all`, `escrow-erc20`, or `counter`; got `{value}`"
            )),
        }
    }

    fn includes(self, family: &str) -> bool {
        match self {
            Self::All => true,
            Self::EscrowErc20 => family == "escrow-erc20",
            Self::Counter => family == "counter",
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let seeds = std::env::args()
        .nth(1)
        .map_or(Ok(20usize), |value| value.parse())?;
    let cohort = std::env::args()
        .nth(2)
        .unwrap_or_else(|| EXPECTED_PIPELINE_PROFILE.to_string());
    let artifact_kind = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "runtime".to_string());
    if !matches!(artifact_kind.as_str(), "runtime" | "creation") {
        return Err("artifact kind must be `runtime` or `creation`".into());
    }
    let mask_constructor_arguments = match std::env::args().nth(4).as_deref() {
        None | Some("no-mask") => false,
        Some("mask") => true,
        Some(_) => return Err("constructor mode must be `no-mask` or `mask`".into()),
    };
    let fixture_selection =
        FixtureSelection::parse(std::env::args().nth(5).as_deref().unwrap_or("all"))?;
    if std::env::args().nth(6).is_some() {
        return Err("too many arguments; expected: [seeds] [cohort] [runtime|creation] [no-mask|mask] [all|escrow-erc20|counter]".into());
    }
    if seeds == 0 {
        return Err("seed count must be positive".into());
    }

    let fixtures = [
        Fixture {
            family: "escrow-erc20",
            deployment: ERC20_DEPLOYMENT,
            runtime: ERC20_RUNTIME,
            constructor_words: vec![
                abi_address([0x11; 20]),
                abi_address([0x22; 20]),
                abi_u256(1_000),
                abi_u256(0),
                abi_u256(0),
            ],
        },
        Fixture {
            family: "counter",
            deployment: COUNTER_DEPLOYMENT,
            runtime: COUNTER_RUNTIME,
            constructor_words: Vec::new(),
        },
    ];

    let fixtures: Vec<_> = fixtures
        .into_iter()
        .filter(|fixture| fixture_selection.includes(fixture.family))
        .collect();
    let expected_samples = fixtures.len() * seeds;
    let mut samples = Vec::with_capacity(expected_samples);
    for fixture in fixtures {
        let deployment = deployment_with_arguments(&fixture)?;
        let runtime = normalize_hex(fixture.runtime);
        let baseline_artifact = if artifact_kind == "creation" {
            deployment.clone()
        } else {
            deploy_runtime(&deployment).map_err(|error| {
                format!(
                    "failed to materialize baseline runtime for {cohort}/{}: {error}",
                    fixture.family
                )
            })?
        };
        for index in 0..seeds {
            let mut config = ObfuscationConfig::with_seed(sequential_seed(index));
            config.obfuscate_constructor_arguments = mask_constructor_arguments;
            match obfuscate_bytecode(&deployment, &runtime, config).await {
                Ok(result) => {
                    if result.integrity.pipeline_profile != EXPECTED_PIPELINE_PROFILE {
                        return Err(format!(
                            "corpus generator expects pipeline profile {}, but Azoth emitted {}",
                            EXPECTED_PIPELINE_PROFILE, result.integrity.pipeline_profile
                        )
                        .into());
                    }
                    let bytecode = if artifact_kind == "creation" {
                        result.obfuscated_bytecode
                    } else {
                        deploy_runtime(&result.obfuscated_bytecode).map_err(|error| {
                            format!(
                                "failed to materialize on-chain runtime for {cohort}/{} seed {index}: {error}",
                                fixture.family
                            )
                        })?
                    };
                    if bytecode_equal(&bytecode, &baseline_artifact)? {
                        return Err(format!(
                            "{cohort}/{} seed {index} produced an exact-identity {artifact_kind} artifact; refusing to label unchanged bytecode as an Azoth-positive sample or emit a partial corpus",
                            fixture.family
                        )
                        .into());
                    }
                    samples.push(CorpusSample {
                        id: format!("{cohort}-{artifact_kind}-{}-{index:04}", fixture.family),
                        bytecode,
                        label: Some(true),
                        family: Some(format!("{artifact_kind}-{}", fixture.family)),
                    });
                }
                Err(error) => {
                    return Err(format!(
                        "failed {cohort}/{} seed {index}; refusing to emit a partial, survivor-biased corpus: {}",
                        fixture.family, error.message
                    )
                    .into());
                }
            }
        }
    }

    assert_eq!(
        samples.len(),
        expected_samples,
        "every requested fixture/seed pair must produce exactly one corpus sample"
    );

    serde_json::to_writer_pretty(std::io::stdout().lock(), &samples)?;
    println!();
    Ok(())
}

fn deployment_with_arguments(fixture: &Fixture) -> Result<String, hex::FromHexError> {
    let mut deployment = hex::decode(normalize_hex(fixture.deployment))?;
    for word in &fixture.constructor_words {
        deployment.extend_from_slice(word);
    }
    Ok(hex::encode(deployment))
}

fn normalize_hex(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '_')
        .collect()
}

fn bytecode_equal(left: &str, right: &str) -> Result<bool, hex::FromHexError> {
    Ok(hex::decode(normalize_hex(left))? == hex::decode(normalize_hex(right))?)
}

fn sequential_seed(index: usize) -> Seed {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
    Seed::from_bytes(bytes)
}

fn abi_address(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn abi_u256(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn deploy_runtime(creation_hex: &str) -> Result<String, String> {
    let creation = hex::decode(creation_hex.trim().trim_start_matches("0x"))
        .map_err(|error| format!("invalid transformed creation hex: {error}"))?;
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
    let outcome = evm
        .transact(TxEnv {
            caller: deployer,
            gas_limit: 30_000_000,
            kind: TxKind::Create,
            data: Bytes::copy_from_slice(&creation),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .map_err(|error| format!("EVM error: {error:?}"))?;

    match outcome.result {
        ExecutionResult::Success {
            output: Output::Create(runtime, Some(_)),
            ..
        } => Ok(format!("0x{}", hex::encode(runtime))),
        ExecutionResult::Success { output, .. } => {
            Err(format!("unexpected successful create output: {output:?}"))
        }
        ExecutionResult::Revert { output, gas_used } => Err(format!(
            "creation reverted with 0x{} (gas {gas_used})",
            hex::encode(output)
        )),
        ExecutionResult::Halt { reason, gas_used } => {
            Err(format!("creation halted with {reason:?} (gas {gas_used})"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_selection_is_explicit_and_deterministic() {
        assert_eq!(FixtureSelection::parse("all"), Ok(FixtureSelection::All));
        assert_eq!(
            FixtureSelection::parse("escrow-erc20"),
            Ok(FixtureSelection::EscrowErc20)
        );
        assert_eq!(
            FixtureSelection::parse("counter"),
            Ok(FixtureSelection::Counter)
        );
        assert!(FixtureSelection::parse("erc20").is_err());

        assert!(FixtureSelection::All.includes("escrow-erc20"));
        assert!(FixtureSelection::All.includes("counter"));
        assert!(FixtureSelection::EscrowErc20.includes("escrow-erc20"));
        assert!(!FixtureSelection::EscrowErc20.includes("counter"));
        assert!(FixtureSelection::Counter.includes("counter"));
        assert!(!FixtureSelection::Counter.includes("escrow-erc20"));
    }

    #[test]
    fn exact_identity_comparison_normalizes_hex_syntax() {
        assert!(bytecode_equal("0x60_00\n5b", "60005B").unwrap());
        assert!(!bytecode_equal("0x60005b", "0x60015b").unwrap());
        assert!(bytecode_equal("0x", "").unwrap());
    }
}
