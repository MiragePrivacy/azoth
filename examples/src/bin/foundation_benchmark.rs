#![recursion_limit = "256"]

//! Reproducible variation benchmark for the Azoth safe foundation profile.
//!
//! The seed corpus is deliberately simple and auditable: seed `i` is 24 zero bytes followed by
//! the big-endian `u64` value `i`. A single run can report prefix checkpoints (normally 10, 100,
//! and 1,000), ensuring every comparison uses the same seed corpus.

use azoth_core::seed::Seed;
use azoth_transform::cluster_shuffle::ClusterShuffle;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig, ObfuscationResult};
use revm::context::result::{ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tokio::task::JoinSet;

const ERC20_DEPLOYMENT: &str = include_str!("../../escrow-bytecode/artifacts/erc20_deployment.hex");
const ERC20_RUNTIME: &str = include_str!("../../escrow-bytecode/artifacts/erc20_runtime.hex");
const NATIVE_DEPLOYMENT: &str =
    include_str!("../../escrow-bytecode/artifacts/native_deployment.hex");
const NATIVE_RUNTIME: &str = include_str!("../../escrow-bytecode/artifacts/native_runtime.hex");
const COUNTER_DEPLOYMENT: &str =
    include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
const COUNTER_RUNTIME: &str = include_str!("../../../tests/bytecode/counter/counter_runtime.hex");
const EXPECTED_PIPELINE_PROFILE: &str = "azoth-foundation-v4";
const SOURCE_FINGERPRINT_ALGORITHM: &str = "azoth-source-tree-sha256-v1: in the root Git worktree and recursively in every initialized tracked submodule, enumerate `git ls-files --cached --others --exclude-standard -z`; replace each gitlink with the recursively enumerated leaf entries beneath its root-relative path and reject uninitialized gitlinks, missing leaves, or leaf types other than regular files and symlinks; represent a regular-file leaf as kind byte 0x00 plus its current file bytes and a symlink leaf as kind byte 0x01 plus its raw link-target bytes; sort leaves lexicographically by raw root-relative path bytes; SHA-256 the ASCII domain `AZOTH_SOURCE_TREE_SHA256_V1` followed by a NUL byte and, for each leaf, its kind byte, u64-be(path byte length), path bytes, u64-be(payload byte length), and payload bytes; encode the digest as lowercase hex";

#[derive(Debug)]
struct Args {
    iterations: usize,
    checkpoints: Vec<usize>,
    json_path: PathBuf,
    csv_path: PathBuf,
    determinism_checks: usize,
    jobs: usize,
    source_revision: String,
}

#[derive(Clone, Copy)]
struct ContractFixture {
    name: &'static str,
    deployment: &'static str,
    runtime: &'static str,
    constructor_kind: ConstructorKind,
}

#[derive(Clone, Copy)]
enum ConstructorKind {
    None,
    Erc20,
    Native,
}

struct SuccessRecord {
    seed_index: usize,
    creation: Vec<u8>,
    runtime: Vec<u8>,
    creation_change_percent: f64,
    runtime_change_percent: f64,
    size_delta_bytes: i64,
    size_delta_percent: f64,
    runtime_size_delta_bytes: i64,
    runtime_size_delta_percent: f64,
    deployment_gas: u64,
    deployment_gas_delta_percent: f64,
    transforms: Vec<String>,
    mapping_fingerprint: Option<String>,
    replay: ReplayCheck,
}

struct FailureRecord {
    seed_index: usize,
    message: String,
    replay: ReplayCheck,
}

struct FailureRowData<'a> {
    contract: &'a str,
    seed_index: usize,
    seed_hex: &'a str,
    message: &'a str,
    replay: ReplayCheck,
    transform_elapsed_ms: f64,
    source_revision: &'a str,
}

struct ContractRun {
    summary: Value,
    rows: Vec<Value>,
    csv: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplayCheck {
    checked: bool,
    exact_output_match: Option<bool>,
    exact_deployment_match: Option<bool>,
}

struct SeedTransformRun {
    seed_index: usize,
    seed_hex: String,
    transform_elapsed_ms: f64,
    first: Result<ObfuscationResult, azoth_transform::obfuscator::ObfuscationError>,
    replay: Option<Result<ObfuscationResult, azoth_transform::obfuscator::ObfuscationError>>,
}

#[derive(Debug, PartialEq)]
struct DeployedVariant {
    creation: Vec<u8>,
    runtime: Vec<u8>,
    deployment_gas: u64,
}

const FIXTURES: [ContractFixture; 3] = [
    ContractFixture {
        name: "escrow_erc20",
        deployment: ERC20_DEPLOYMENT,
        runtime: ERC20_RUNTIME,
        constructor_kind: ConstructorKind::Erc20,
    },
    ContractFixture {
        name: "escrow_native",
        deployment: NATIVE_DEPLOYMENT,
        runtime: NATIVE_RUNTIME,
        constructor_kind: ConstructorKind::Native,
    },
    ContractFixture {
        name: "counter",
        deployment: COUNTER_DEPLOYMENT,
        runtime: COUNTER_RUNTIME,
        constructor_kind: ConstructorKind::None,
    },
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let started = Instant::now();
    let generated_at = chrono::Utc::now().to_rfc3339();

    println!(
        "Azoth foundation benchmark: {} seeds, checkpoints {:?}",
        args.iterations, args.checkpoints
    );

    let mut summaries = Vec::new();
    let mut rows = Vec::new();
    let mut csv = String::from(
        "contract,seed_index,seed_hex,status,error,exact_replay_checked,exact_output_replay_match,exact_deployment_replay_match,original_creation_bytes,obfuscated_creation_bytes,creation_size_delta_bytes,creation_size_delta_percent,creation_changed_positions,creation_change_percent,original_runtime_bytes,obfuscated_runtime_bytes,runtime_size_delta_bytes,runtime_size_delta_percent,runtime_changed_positions,runtime_change_percent,original_deployment_gas,obfuscated_deployment_gas,deployment_gas_delta_percent,transforms,constructor_args_obfuscated,blocks_created,instructions_added,transform_elapsed_ms,benchmark_schema,pipeline_profile,source_revision,original_creation_keccak256,obfuscated_creation_keccak256,original_runtime_keccak256,obfuscated_runtime_keccak256,obfuscation_result_keccak256\n",
    );

    for fixture in FIXTURES {
        let run = run_contract(fixture, &args).await?;
        summaries.push(run.summary);
        rows.extend(run.rows);
        csv.push_str(&run.csv);
    }

    let report = json!({
        "schema": "azoth-foundation-benchmark-v4",
        "generated_at": generated_at,
        "iterations_per_contract": args.iterations,
        "checkpoints": args.checkpoints,
        "determinism_checks_per_contract": args.determinism_checks.min(args.iterations),
        "parallel_jobs": args.jobs,
        "source_identity": {
            "declared_revision": args.source_revision,
            "declared_revision_is_caller_asserted": true,
            "declared_revision_verified_by_harness": false,
            "source_fingerprint_algorithm": SOURCE_FINGERPRINT_ALGORITHM,
            "workspace_package_version": env!("CARGO_PKG_VERSION"),
            "cargo_lock_keccak256": keccak256_hex(include_bytes!("../../../Cargo.lock")),
            "declaration_note": "declared_revision is supplied by the benchmark caller, is not verified by this process, and should contain both the base Git revision and a source fingerprint computed with source_fingerprint_algorithm"
        },
        "seed_scheme": "32-byte big-endian uint256(seed_index); indices are consecutive from zero",
        "pipeline": {
            "profile": EXPECTED_PIPELINE_PROFILE,
            "explicit_user_transforms": ["ClusterShuffle"],
            "automatic_pipeline_stages": [],
            "removed_suffixes": "compiler auxdata and padding are preserved byte-for-byte; layout changes require a terminal, fully resolved runtime boundary",
            "function_selectors": "preserved unchanged in the safe profile",
            "constructor_arguments": "preserved unchanged in the safe profile",
            "decoder_preserves_raw_unknown_bytes": true,
            "unknown_executable_opcode_policy": "fail closed: reject unmodelled UNKNOWN opcodes and raw INVALID values other than 0xfe"
        },
        "metric_definition": {
            "positional_change_percent": "(unequal aligned bytes + absolute length difference) / max(lengths) * 100",
            "pairwise_diversity": "the same positional metric across every pair when there are at most 10,000 pairs, otherwise 10,000 distinct deterministic sampled unordered pairs",
            "deployment_check": "Both fixture and transformed creation bytecode must deploy successfully in REVM; runtime metrics use the returned deployed bytecode rather than an internal intermediate buffer.",
            "exact_replay": "Canonical complete ObfuscationResult equality, including the diagnostic trace, plus identical REVM deployed runtime and deployment gas for the same input and seed.",
            "complete_result_hash": "obfuscation_result_keccak256 is Keccak-256 of the compact serde_json serialization of the complete ObfuscationResult; the result schema uses deterministic serializers for unordered maps",
            "successful_sample_scope": "Variation, size, gas, uniqueness, and pairwise distributions include successful deployments only; requested-seed success/failure counts are reported beside them.",
            "output_identity_classification": "A successful output is exact_identity only when both transformed creation bytecode and materialized deployed runtime are byte-for-byte equal to their baselines; every other successful output is changed. Changed-output rates use successful deployments as their denominator.",
            "report_reproducibility": "Seed prefixes and pipeline outputs are reproducible; generated_at, wall_time_seconds, and transform_elapsed_ms are observational timing fields and are not expected to be byte-identical across runs.",
            "note": "Positional change is Hamming distance over the shared prefix plus length difference. It is intentionally not labeled Levenshtein edit distance. Successful deployment is a smoke test, not a proof of behavioral equivalence."
        },
        "wall_time_seconds": started.elapsed().as_secs_f64(),
        "contracts": summaries,
        "runs": rows,
    });

    if let Some(parent) = args.json_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = args.csv_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.json_path, serde_json::to_string_pretty(&report)?)?;
    fs::write(&args.csv_path, csv)?;

    println!("JSON: {}", args.json_path.display());
    println!("CSV:  {}", args.csv_path.display());
    println!("Wall time: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

async fn run_contract(
    fixture: ContractFixture,
    args: &Args,
) -> Result<ContractRun, Box<dyn Error>> {
    let deployment_hex = full_deployment_hex(fixture)?;
    let runtime_hex = normalized_hex(fixture.runtime);
    let original_creation = hex::decode(&deployment_hex)?;
    let fixture_runtime = hex::decode(&runtime_hex)?;
    let (original_runtime, original_deployment_gas) = deploy_creation(&original_creation)
        .map_err(|message| format!("{} original deployment failed: {message}", fixture.name))?;
    if original_runtime.len() != fixture_runtime.len() {
        return Err(format!(
            "{} fixture runtime length ({}) differs from the runtime returned by its creation bytecode ({})",
            fixture.name,
            fixture_runtime.len(),
            original_runtime.len(),
        )
        .into());
    }
    // The exact artifact runtime remains the authoritative init/runtime boundary passed to Azoth.
    // The deployed baseline is used for measurements because constructors can patch immutables
    // (the ERC20 escrow writes its token address into four runtime locations).
    let (fixture_runtime_changed_positions, fixture_runtime_change_percent) =
        positional_difference(&fixture_runtime, &original_runtime);
    let mut successes = Vec::with_capacity(args.iterations);
    let mut failures = Vec::new();
    let mut rows = Vec::with_capacity(args.iterations);
    let mut csv = String::new();
    let mut exact_output_replay_mismatches = 0usize;
    let mut exact_deployment_replay_mismatches = 0usize;
    let contract_started = Instant::now();
    let original_creation_hash = keccak256_hex(&original_creation);
    let original_runtime_hash = keccak256_hex(&original_runtime);

    println!(
        "[{}] original creation={} B runtime={} B",
        fixture.name,
        original_creation.len(),
        original_runtime.len()
    );

    for batch_start in (0..args.iterations).step_by(args.jobs) {
        let batch_end = (batch_start + args.jobs).min(args.iterations);
        let mut workers = JoinSet::new();
        for seed_index in batch_start..batch_end {
            let deployment_hex = deployment_hex.clone();
            let runtime_hex = runtime_hex.clone();
            let check_replay = seed_index < args.determinism_checks;
            workers.spawn(async move {
                let seed = sequential_seed(seed_index);
                let seed_hex = seed.to_hex();
                let case_started = Instant::now();
                let first =
                    obfuscate_with_safe_profile(&deployment_hex, &runtime_hex, seed.clone()).await;
                let transform_elapsed_ms = case_started.elapsed().as_secs_f64() * 1_000.0;
                let replay = if check_replay {
                    Some(obfuscate_with_safe_profile(&deployment_hex, &runtime_hex, seed).await)
                } else {
                    None
                };
                SeedTransformRun {
                    seed_index,
                    seed_hex,
                    transform_elapsed_ms,
                    first,
                    replay,
                }
            });
        }

        let mut batch_runs = Vec::with_capacity(batch_end - batch_start);
        while let Some(joined) = workers.join_next().await {
            batch_runs.push(joined.map_err(|error| format!("benchmark worker failed: {error}"))?);
        }
        batch_runs.sort_by_key(|run| run.seed_index);

        for SeedTransformRun {
            seed_index,
            seed_hex,
            transform_elapsed_ms,
            first,
            replay,
        } in batch_runs
        {
            let mut replay_check = ReplayCheck {
                checked: replay.is_some(),
                exact_output_match: replay
                    .as_ref()
                    .map(|second| same_complete_outcome(&first, second)),
                exact_deployment_match: None,
            };
            if replay_check.exact_output_match == Some(false) {
                exact_output_replay_mismatches += 1;
            }

            match first {
                Ok(result) => {
                    if result.integrity.pipeline_profile != EXPECTED_PIPELINE_PROFILE {
                        let message = format!(
                            "benchmark profile mismatch: harness expects {}, pipeline emitted {}",
                            EXPECTED_PIPELINE_PROFILE, result.integrity.pipeline_profile
                        );
                        record_failure(
                            &mut rows,
                            &mut csv,
                            FailureRowData {
                                contract: fixture.name,
                                seed_index,
                                seed_hex: &seed_hex,
                                message: &message,
                                replay: replay_check,
                                transform_elapsed_ms,
                                source_revision: &args.source_revision,
                            },
                        )?;
                        failures.push(FailureRecord {
                            seed_index,
                            message,
                            replay: replay_check,
                        });
                        continue;
                    }
                    let deployed = deployment_from_result(&result);
                    if let (Ok(deployed), Some(second)) = (&deployed, replay.as_ref()) {
                        replay_check.exact_deployment_match = Some(match second {
                            Ok(replay_result) => deployment_from_result(replay_result)
                                .as_ref()
                                .is_ok_and(|replay_deployed| replay_deployed == deployed),
                            Err(_) => false,
                        });
                        if replay_check.exact_deployment_match == Some(false) {
                            exact_deployment_replay_mismatches += 1;
                        }
                    }
                    let DeployedVariant {
                        creation,
                        runtime,
                        deployment_gas,
                    } = match deployed {
                        Ok(deployed) => deployed,
                        Err(message) => {
                            record_failure(
                                &mut rows,
                                &mut csv,
                                FailureRowData {
                                    contract: fixture.name,
                                    seed_index,
                                    seed_hex: &seed_hex,
                                    message: &message,
                                    replay: replay_check,
                                    transform_elapsed_ms,
                                    source_revision: &args.source_revision,
                                },
                            )?;
                            failures.push(FailureRecord {
                                seed_index,
                                message,
                                replay: replay_check,
                            });
                            continue;
                        }
                    };
                    let (creation_changed, creation_change_percent) =
                        positional_difference(&original_creation, &creation);
                    let (runtime_changed, runtime_change_percent) =
                        positional_difference(&original_runtime, &runtime);
                    let size_delta_bytes = creation.len() as i64 - original_creation.len() as i64;
                    let size_delta_percent = percent_delta(original_creation.len(), creation.len());
                    let runtime_size_delta_bytes =
                        runtime.len() as i64 - original_runtime.len() as i64;
                    let runtime_size_delta_percent =
                        percent_delta(original_runtime.len(), runtime.len());
                    let deployment_gas_delta_percent =
                        percent_delta_u64(original_deployment_gas, deployment_gas);
                    let transforms = result.metadata.transforms_applied.clone();
                    let mapping_fingerprint = selector_mapping_fingerprint(&result);
                    let obfuscated_creation_hash = keccak256_hex(&creation);
                    let obfuscated_runtime_hash = keccak256_hex(&runtime);
                    let obfuscation_result_hash = keccak256_hex(&serde_json::to_vec(&result)?);

                    rows.push(json!({
                        "benchmark_schema": "azoth-foundation-benchmark-v4",
                        "pipeline_profile": EXPECTED_PIPELINE_PROFILE,
                        "source_revision": args.source_revision,
                        "contract": fixture.name,
                        "seed_index": seed_index,
                        "seed_hex": seed_hex,
                        "status": "ok",
                        "exact_replay_checked": replay_check.checked,
                        "exact_output_replay_match": replay_check.exact_output_match,
                        "exact_deployment_replay_match": replay_check.exact_deployment_match,
                        "original_creation_bytes": original_creation.len(),
                        "obfuscated_creation_bytes": creation.len(),
                        "creation_size_delta_bytes": size_delta_bytes,
                        "creation_size_delta_percent": size_delta_percent,
                        "creation_changed_positions": creation_changed,
                        "creation_change_percent": creation_change_percent,
                        "original_runtime_bytes": original_runtime.len(),
                        "obfuscated_runtime_bytes": runtime.len(),
                        "original_creation_keccak256": original_creation_hash,
                        "obfuscated_creation_keccak256": obfuscated_creation_hash,
                        "original_runtime_keccak256": original_runtime_hash,
                        "obfuscated_runtime_keccak256": obfuscated_runtime_hash,
                        "obfuscation_result_keccak256": obfuscation_result_hash,
                        "runtime_size_delta_bytes": runtime_size_delta_bytes,
                        "runtime_size_delta_percent": runtime_size_delta_percent,
                        "runtime_changed_positions": runtime_changed,
                        "runtime_change_percent": runtime_change_percent,
                        "original_deployment_gas": original_deployment_gas,
                        "obfuscated_deployment_gas": deployment_gas,
                        "deployment_gas_delta_percent": deployment_gas_delta_percent,
                        "transforms": transforms,
                        "constructor_args_obfuscated": result.metadata.constructor_args_obfuscated,
                        "blocks_created": result.blocks_created,
                        "instructions_added": result.instructions_added,
                        "transform_elapsed_ms": transform_elapsed_ms,
                    }));
                    append_csv_row(
                        &mut csv,
                        &[
                            fixture.name.to_string(),
                            seed_index.to_string(),
                            seed_hex,
                            "ok".to_string(),
                            String::new(),
                            replay_check.checked.to_string(),
                            optional_bool(replay_check.exact_output_match),
                            optional_bool(replay_check.exact_deployment_match),
                            original_creation.len().to_string(),
                            creation.len().to_string(),
                            size_delta_bytes.to_string(),
                            format!("{size_delta_percent:.6}"),
                            creation_changed.to_string(),
                            format!("{creation_change_percent:.6}"),
                            original_runtime.len().to_string(),
                            runtime.len().to_string(),
                            runtime_size_delta_bytes.to_string(),
                            format!("{runtime_size_delta_percent:.6}"),
                            runtime_changed.to_string(),
                            format!("{runtime_change_percent:.6}"),
                            original_deployment_gas.to_string(),
                            deployment_gas.to_string(),
                            format!("{deployment_gas_delta_percent:.6}"),
                            transforms.join("|"),
                            result.metadata.constructor_args_obfuscated.to_string(),
                            result.blocks_created.to_string(),
                            result.instructions_added.to_string(),
                            format!("{transform_elapsed_ms:.6}"),
                            "azoth-foundation-benchmark-v4".to_string(),
                            EXPECTED_PIPELINE_PROFILE.to_string(),
                            args.source_revision.clone(),
                            original_creation_hash.clone(),
                            obfuscated_creation_hash,
                            original_runtime_hash.clone(),
                            obfuscated_runtime_hash,
                            obfuscation_result_hash,
                        ],
                    )?;

                    successes.push(SuccessRecord {
                        seed_index,
                        creation,
                        runtime,
                        creation_change_percent,
                        runtime_change_percent,
                        size_delta_bytes,
                        size_delta_percent,
                        runtime_size_delta_bytes,
                        runtime_size_delta_percent,
                        deployment_gas,
                        deployment_gas_delta_percent,
                        transforms,
                        mapping_fingerprint,
                        replay: replay_check,
                    });
                }
                Err(error) => {
                    let message = error.to_string();
                    record_failure(
                        &mut rows,
                        &mut csv,
                        FailureRowData {
                            contract: fixture.name,
                            seed_index,
                            seed_hex: &seed_hex,
                            message: &message,
                            replay: replay_check,
                            transform_elapsed_ms,
                            source_revision: &args.source_revision,
                        },
                    )?;
                    failures.push(FailureRecord {
                        seed_index,
                        message,
                        replay: replay_check,
                    });
                }
            }
        }
        println!(
            "[{}] {}/{} seeds (ok={}, failed={})",
            fixture.name,
            batch_end,
            args.iterations,
            successes.len(),
            failures.len()
        );
    }

    let checkpoint_summaries: Vec<Value> = args
        .checkpoints
        .iter()
        .copied()
        .filter(|checkpoint| *checkpoint <= args.iterations)
        .map(|checkpoint| {
            summarize_checkpoint(
                checkpoint,
                &successes,
                &failures,
                &original_creation,
                &original_runtime,
                original_deployment_gas,
            )
        })
        .collect();
    let exact_identity_outputs = successes
        .iter()
        .filter(|record| is_exact_identity(record, &original_creation, &original_runtime))
        .count();
    let changed_outputs = successes.len() - exact_identity_outputs;

    Ok(ContractRun {
        summary: json!({
            "name": fixture.name,
            "requested_seeds": args.iterations,
            "successes": successes.len(),
            "failures": failures.len(),
            "exact_identity_outputs": exact_identity_outputs,
            "changed_outputs": changed_outputs,
            "changed_output_rate_percent_of_successes": ratio_percent(changed_outputs, successes.len()),
            "original_creation_bytes": original_creation.len(),
            "original_runtime_bytes": original_runtime.len(),
            "original_deployment_gas": original_deployment_gas,
            "runtime_artifact_template_changed_positions_after_constructor": fixture_runtime_changed_positions,
            "runtime_artifact_template_change_percent_after_constructor": fixture_runtime_change_percent,
            "constructor_argument_bytes": original_creation.len()
                .saturating_sub(hex::decode(normalized_hex(fixture.deployment))?.len()),
            "exact_replay_checks": args.determinism_checks.min(args.iterations),
            "exact_output_replay_mismatches": exact_output_replay_mismatches,
            "exact_deployment_replay_mismatches": exact_deployment_replay_mismatches,
            "wall_time_seconds": contract_started.elapsed().as_secs_f64(),
            "checkpoints": checkpoint_summaries,
        }),
        rows,
        csv,
    })
}

async fn obfuscate_with_safe_profile(
    deployment_hex: &str,
    runtime_hex: &str,
    seed: Seed,
) -> Result<ObfuscationResult, azoth_transform::obfuscator::ObfuscationError> {
    obfuscate_bytecode(deployment_hex, runtime_hex, safe_profile(seed)).await
}

fn safe_profile(seed: Seed) -> ObfuscationConfig {
    // Pin the audited foundation profile. Auxdata and padding are preserved byte-for-byte.
    // Selector rewriting and constructor masking stay disabled until their semantic and detector
    // gates pass.
    ObfuscationConfig {
        seed,
        transforms: vec![Box::new(ClusterShuffle::new())],
        preserve_unknown_opcodes: true,
        rewrite_function_selectors: false,
        obfuscate_constructor_arguments: false,
    }
}

fn same_complete_outcome(
    left: &Result<ObfuscationResult, azoth_transform::obfuscator::ObfuscationError>,
    right: &Result<ObfuscationResult, azoth_transform::obfuscator::ObfuscationError>,
) -> bool {
    match (left, right) {
        (Ok(a), Ok(b)) => match (serde_json::to_vec(a), serde_json::to_vec(b)) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        },
        (Err(a), Err(b)) => {
            a.message == b.message
                && match (serde_json::to_vec(&a.trace), serde_json::to_vec(&b.trace)) {
                    (Ok(left), Ok(right)) => left == right,
                    _ => false,
                }
        }
        _ => false,
    }
}

fn deployment_from_result(result: &ObfuscationResult) -> Result<DeployedVariant, String> {
    let creation = decode_result_hex(&result.obfuscated_bytecode)
        .map_err(|error| format!("transformed creation hex is invalid: {error}"))?;
    let (runtime, deployment_gas) = deploy_creation(&creation)
        .map_err(|error| format!("transformed deployment failed: {error}"))?;
    let reported_runtime = decode_result_hex(&result.obfuscated_runtime)
        .map_err(|error| format!("reported runtime hex is invalid: {error}"))?;
    // The reported runtime is complete, but constructor execution can patch immutable words into
    // it, so byte equality would incorrectly reject valid ERC20 deployments. Length must remain
    // exact, and the deployed REVM result is authoritative for all runtime measurements.
    if reported_runtime.len() != runtime.len() {
        return Err(format!(
            "pipeline reported runtime length differs from REVM deployed runtime (deployed={} B, reported={} B)",
            runtime.len(),
            reported_runtime.len(),
        ));
    }
    Ok(DeployedVariant {
        creation,
        runtime,
        deployment_gas,
    })
}

fn summarize_checkpoint(
    checkpoint: usize,
    successes: &[SuccessRecord],
    failures: &[FailureRecord],
    original_creation: &[u8],
    original_runtime: &[u8],
    original_deployment_gas: u64,
) -> Value {
    let subset: Vec<&SuccessRecord> = successes
        .iter()
        .filter(|record| record.seed_index < checkpoint)
        .collect();
    let failure_subset: Vec<&FailureRecord> = failures
        .iter()
        .filter(|record| record.seed_index < checkpoint)
        .collect();
    let observed_seed_indices: HashSet<_> = subset
        .iter()
        .map(|record| record.seed_index)
        .chain(failure_subset.iter().map(|record| record.seed_index))
        .collect();
    assert_eq!(
        subset.len() + failure_subset.len(),
        checkpoint,
        "checkpoint must contain exactly one outcome per requested seed"
    );
    assert_eq!(
        observed_seed_indices.len(),
        checkpoint,
        "checkpoint must contain exactly one outcome for every seed in its prefix"
    );
    assert!(
        (0..checkpoint).all(|seed_index| observed_seed_indices.contains(&seed_index)),
        "checkpoint is missing an outcome from its requested seed prefix"
    );
    let replay_checks: Vec<ReplayCheck> = subset
        .iter()
        .map(|record| record.replay)
        .chain(failure_subset.iter().map(|record| record.replay))
        .filter(|check| check.checked)
        .collect();
    let exact_output_replay_mismatches = replay_checks
        .iter()
        .filter(|check| check.exact_output_match == Some(false))
        .count();
    let deployment_replay_checks = replay_checks
        .iter()
        .filter(|check| check.exact_deployment_match.is_some())
        .count();
    let exact_deployment_replay_mismatches = replay_checks
        .iter()
        .filter(|check| check.exact_deployment_match == Some(false))
        .count();
    let exact_identity_outputs = subset
        .iter()
        .filter(|record| is_exact_identity(record, original_creation, original_runtime))
        .count();
    let changed_outputs = subset.len() - exact_identity_outputs;

    let creation_change: Vec<f64> = subset
        .iter()
        .map(|record| record.creation_change_percent)
        .collect();
    let runtime_change: Vec<f64> = subset
        .iter()
        .map(|record| record.runtime_change_percent)
        .collect();
    let size_delta_bytes: Vec<f64> = subset
        .iter()
        .map(|record| record.size_delta_bytes as f64)
        .collect();
    let size_delta_percent: Vec<f64> = subset
        .iter()
        .map(|record| record.size_delta_percent)
        .collect();
    let runtime_size_delta_bytes: Vec<f64> = subset
        .iter()
        .map(|record| record.runtime_size_delta_bytes as f64)
        .collect();
    let runtime_size_delta_percent: Vec<f64> = subset
        .iter()
        .map(|record| record.runtime_size_delta_percent)
        .collect();
    let creation_sizes: Vec<f64> = subset
        .iter()
        .map(|record| record.creation.len() as f64)
        .collect();
    let runtime_sizes: Vec<f64> = subset
        .iter()
        .map(|record| record.runtime.len() as f64)
        .collect();
    let deployment_gas: Vec<f64> = subset
        .iter()
        .map(|record| record.deployment_gas as f64)
        .collect();
    let deployment_gas_delta_percent: Vec<f64> = subset
        .iter()
        .map(|record| record.deployment_gas_delta_percent)
        .collect();
    let unique_creation = subset
        .iter()
        .map(|record| &record.creation)
        .collect::<HashSet<_>>()
        .len();
    let unique_runtime = subset
        .iter()
        .map(|record| &record.runtime)
        .collect::<HashSet<_>>()
        .len();
    let mapping_subset: Vec<&String> = subset
        .iter()
        .filter_map(|record| record.mapping_fingerprint.as_ref())
        .collect();
    let unique_mappings = mapping_subset.iter().copied().collect::<HashSet<_>>().len();

    let mut transform_counts = BTreeMap::<String, usize>::new();
    for record in &subset {
        for transform in &record.transforms {
            *transform_counts.entry(transform.clone()).or_default() += 1;
        }
    }
    let mut failure_counts = BTreeMap::<String, usize>::new();
    for failure in &failure_subset {
        *failure_counts.entry(failure.message.clone()).or_default() += 1;
    }

    let creation_pairwise = pairwise_diversity(&subset, |record| &record.creation);
    let runtime_pairwise = pairwise_diversity(&subset, |record| &record.runtime);

    json!({
        "requested_seeds": checkpoint,
        "seed_prefix_start_inclusive": 0,
        "seed_prefix_end_exclusive": checkpoint,
        "seed_prefix_complete": true,
        "successes": subset.len(),
        "failures": failure_subset.len(),
        "success_rate_percent": ratio_percent(subset.len(), checkpoint),
        "exact_identity_outputs": exact_identity_outputs,
        "changed_outputs": changed_outputs,
        "changed_output_rate_percent_of_successes": ratio_percent(changed_outputs, subset.len()),
        "exact_output_replay_checks": replay_checks.len(),
        "exact_output_replay_mismatches": exact_output_replay_mismatches,
        "exact_deployment_replay_checks": deployment_replay_checks,
        "exact_deployment_replay_mismatches": exact_deployment_replay_mismatches,
        "original_creation_bytes": original_creation.len(),
        "original_runtime_bytes": original_runtime.len(),
        "original_deployment_gas": original_deployment_gas,
        "creation_change_percent": descriptive_stats(&creation_change),
        "runtime_change_percent": descriptive_stats(&runtime_change),
        "creation_size_bytes": descriptive_stats(&creation_sizes),
        "runtime_size_bytes": descriptive_stats(&runtime_sizes),
        "creation_size_delta_bytes": descriptive_stats(&size_delta_bytes),
        "creation_size_delta_percent": descriptive_stats(&size_delta_percent),
        "runtime_size_delta_bytes": descriptive_stats(&runtime_size_delta_bytes),
        "runtime_size_delta_percent": descriptive_stats(&runtime_size_delta_percent),
        "deployment_gas": descriptive_stats(&deployment_gas),
        "deployment_gas_delta_percent": descriptive_stats(&deployment_gas_delta_percent),
        "unique_creation_outputs": unique_creation,
        "unique_creation_percent": ratio_percent(unique_creation, subset.len()),
        "unique_runtime_outputs": unique_runtime,
        "unique_runtime_percent": ratio_percent(unique_runtime, subset.len()),
        "selector_mappings_observed": mapping_subset.len(),
        "unique_selector_mappings": unique_mappings,
        "creation_pairwise_change_percent": creation_pairwise,
        "runtime_pairwise_change_percent": runtime_pairwise,
        "transforms_applied_counts": transform_counts,
        "failure_counts": failure_counts,
    })
}

fn is_exact_identity(
    record: &SuccessRecord,
    original_creation: &[u8],
    original_runtime: &[u8],
) -> bool {
    record.creation == original_creation && record.runtime == original_runtime
}

fn pairwise_diversity<F>(records: &[&SuccessRecord], bytes: F) -> Value
where
    F: Fn(&SuccessRecord) -> &[u8],
{
    let count = records.len();
    if count < 2 {
        return json!({
            "pairs": 0,
            "possible_pairs": 0,
            "sampling": "all_pairs",
            "stats": descriptive_stats(&[]),
        });
    }

    let total_pairs = (count as u128) * ((count - 1) as u128) / 2;
    let target_pairs = usize::try_from(total_pairs.min(10_000)).expect("sample cap fits usize");
    let mut values = Vec::with_capacity(target_pairs);

    if total_pairs <= 10_000 {
        for left in 0..count {
            for right in (left + 1)..count {
                values.push(positional_difference(bytes(records[left]), bytes(records[right])).1);
            }
        }
    } else {
        // SplitMix64 sampling makes the pair set independent of OS entropy and iteration timing.
        // Its mixed output avoids the short modulo cycles produced by sampling raw LCG state. The
        // HashSet prevents duplicate or directionally repeated unordered pairs.
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ count as u64;
        let mut sampled = HashSet::with_capacity(target_pairs);
        while values.len() < target_pairs {
            let mut left = splitmix64(&mut state) as usize % count;
            let mut right = splitmix64(&mut state) as usize % count;
            if left == right {
                right = (right + 1) % count;
            }
            if left > right {
                std::mem::swap(&mut left, &mut right);
            }
            if sampled.insert((left, right)) {
                values.push(positional_difference(bytes(records[left]), bytes(records[right])).1);
            }
        }
    }

    json!({
        "pairs": values.len(),
        "possible_pairs": total_pairs,
        "sampling": if total_pairs <= 10_000 { "all_pairs" } else { "distinct_deterministic_splitmix64_sample" },
        "stats": descriptive_stats(&values),
    })
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn descriptive_stats(values: &[f64]) -> Value {
    if values.is_empty() {
        return json!({
            "count": 0,
            "mean": Value::Null,
            "min": Value::Null,
            "p50": Value::Null,
            "p95": Value::Null,
            "max": Value::Null,
        });
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    json!({
        "count": sorted.len(),
        "mean": mean,
        "min": sorted[0],
        "p50": percentile(&sorted, 0.50),
        "p95": percentile(&sorted, 0.95),
        "max": sorted[sorted.len() - 1],
    })
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0];
    }
    let position = quantile * (sorted.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        sorted[lower] + (position - lower as f64) * (sorted[upper] - sorted[lower])
    }
}

fn full_deployment_hex(fixture: ContractFixture) -> Result<String, Box<dyn Error>> {
    let mut deployment = hex::decode(normalized_hex(fixture.deployment))?;
    match fixture.constructor_kind {
        ConstructorKind::None => {}
        ConstructorKind::Erc20 => {
            deployment.extend_from_slice(&abi_address([0x11; 20]));
            deployment.extend_from_slice(&abi_address([0x22; 20]));
            deployment.extend_from_slice(&abi_u256(1_000));
            deployment.extend_from_slice(&abi_u256(0));
            deployment.extend_from_slice(&abi_u256(0));
        }
        ConstructorKind::Native => {
            deployment.extend_from_slice(&abi_address([0x22; 20]));
            deployment.extend_from_slice(&abi_u256(1_000));
            deployment.extend_from_slice(&abi_u256(0));
            deployment.extend_from_slice(&abi_u256(0));
        }
    }
    Ok(hex::encode(deployment))
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

fn sequential_seed(index: usize) -> Seed {
    let mut bytes = [0u8; 32];
    let index_bytes = index.to_be_bytes();
    let offset = bytes.len() - index_bytes.len();
    bytes[offset..].copy_from_slice(&index_bytes);
    Seed::from_bytes(bytes)
}

fn positional_difference(left: &[u8], right: &[u8]) -> (usize, f64) {
    let aligned_mismatches = left.iter().zip(right).filter(|(a, b)| a != b).count();
    let changed = aligned_mismatches + left.len().abs_diff(right.len());
    let denominator = left.len().max(right.len());
    let percent = if denominator == 0 {
        0.0
    } else {
        changed as f64 / denominator as f64 * 100.0
    };
    (changed, percent)
}

fn percent_delta(original: usize, transformed: usize) -> f64 {
    if original == 0 {
        0.0
    } else {
        (transformed as f64 - original as f64) / original as f64 * 100.0
    }
}

fn percent_delta_u64(original: u64, transformed: u64) -> f64 {
    if original == 0 {
        0.0
    } else {
        (transformed as f64 - original as f64) / original as f64 * 100.0
    }
}

fn ratio_percent(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64 * 100.0
    }
}

fn selector_mapping_fingerprint(result: &ObfuscationResult) -> Option<String> {
    let mapping = result.selector_mapping.as_ref()?;
    let mut entries: Vec<_> = mapping.iter().collect();
    entries.sort_by_key(|(selector, _)| **selector);
    let mut fingerprint = String::new();
    for (selector, token) in entries {
        let _ = write!(fingerprint, "{selector:08x}:{};", hex::encode(token));
    }
    Some(fingerprint)
}

fn decode_result_hex(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(input.trim().trim_start_matches("0x"))
}

fn deploy_creation(creation: &[u8]) -> Result<(Vec<u8>, u64), String> {
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
            data: Bytes::copy_from_slice(creation),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .map_err(|error| format!("EVM error: {error:?}"))?;

    match outcome.result {
        ExecutionResult::Success {
            output: Output::Create(runtime, Some(_)),
            gas_used,
            ..
        } => Ok((runtime.to_vec(), gas_used)),
        ExecutionResult::Success {
            output, gas_used, ..
        } => Err(format!(
            "unexpected successful create output {output:?} (gas {gas_used})"
        )),
        ExecutionResult::Revert { output, gas_used } => Err(format!(
            "reverted with 0x{} (gas {gas_used})",
            hex::encode(output)
        )),
        ExecutionResult::Halt { reason, gas_used } => {
            Err(format!("halted with {reason:?} (gas {gas_used})"))
        }
    }
}

fn normalized_hex(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '_')
        .collect()
}

fn record_failure(
    rows: &mut Vec<Value>,
    csv: &mut String,
    failure: FailureRowData<'_>,
) -> std::fmt::Result {
    let FailureRowData {
        contract,
        seed_index,
        seed_hex,
        message,
        replay,
        transform_elapsed_ms,
        source_revision,
    } = failure;
    rows.push(json!({
        "benchmark_schema": "azoth-foundation-benchmark-v4",
        "pipeline_profile": EXPECTED_PIPELINE_PROFILE,
        "source_revision": source_revision,
        "contract": contract,
        "seed_index": seed_index,
        "seed_hex": seed_hex,
        "status": "error",
        "error": message,
        "exact_replay_checked": replay.checked,
        "exact_output_replay_match": replay.exact_output_match,
        "exact_deployment_replay_match": replay.exact_deployment_match,
        "transform_elapsed_ms": transform_elapsed_ms,
    }));
    let mut columns = vec![String::new(); 36];
    columns[0] = contract.to_string();
    columns[1] = seed_index.to_string();
    columns[2] = seed_hex.to_string();
    columns[3] = "error".to_string();
    columns[4] = message.to_string();
    columns[5] = replay.checked.to_string();
    columns[6] = optional_bool(replay.exact_output_match);
    columns[7] = optional_bool(replay.exact_deployment_match);
    columns[27] = format!("{transform_elapsed_ms:.6}");
    columns[28] = "azoth-foundation-benchmark-v4".to_string();
    columns[29] = EXPECTED_PIPELINE_PROFILE.to_string();
    columns[30] = source_revision.to_string();
    append_csv_row(csv, &columns)
}

fn append_csv_row(output: &mut String, columns: &[String]) -> std::fmt::Result {
    debug_assert_eq!(columns.len(), 36);
    for (index, cell) in columns.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        if cell
            .chars()
            .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
        {
            write!(output, "{}", csv_quote(cell))?;
        } else {
            output.push_str(cell);
        }
    }
    output.push('\n');
    Ok(())
}

fn optional_bool(value: Option<bool>) -> String {
    value.map(|inner| inner.to_string()).unwrap_or_default()
}

fn csv_quote(input: &str) -> String {
    format!("\"{}\"", input.replace('"', "\"\""))
}

fn keccak256_hex(bytes: &[u8]) -> String {
    hex::encode(Keccak256::digest(bytes))
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut iterations = 1_000usize;
    let mut checkpoints = vec![10usize, 100, 1_000];
    let mut json_path: Option<PathBuf> = None;
    let mut csv_path: Option<PathBuf> = None;
    let mut determinism_checks: Option<usize> = None;
    let mut source_revision: Option<String> = None;
    let mut jobs = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(8);
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--iterations" | "-i" => {
                iterations = arguments
                    .next()
                    .ok_or("--iterations requires a value")?
                    .parse()?;
            }
            "--checkpoints" => {
                let raw = arguments.next().ok_or("--checkpoints requires a value")?;
                checkpoints = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::parse)
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "--json" => {
                json_path = Some(PathBuf::from(
                    arguments.next().ok_or("--json requires a path")?,
                ));
            }
            "--csv" => {
                csv_path = Some(PathBuf::from(
                    arguments.next().ok_or("--csv requires a path")?,
                ));
            }
            "--determinism-checks" => {
                determinism_checks = Some(
                    arguments
                        .next()
                        .ok_or("--determinism-checks requires a value")?
                        .parse()?,
                );
            }
            "--jobs" | "-j" => {
                jobs = arguments.next().ok_or("--jobs requires a value")?.parse()?;
            }
            "--source-revision" => {
                source_revision = Some(
                    arguments
                        .next()
                        .ok_or("--source-revision requires a value")?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: cargo run --locked --release -p azoth-examples --bin foundation_benchmark -- \\\n                     --iterations 1000 --checkpoints 10,100,1000 \\\n                     --determinism-checks 1000 \\\n                     --source-revision 'base:<git-sha>;tree-sha256:<content-sha>' \\\n                     --json /tmp/azoth-foundation-benchmark.json \\\n                     --csv /tmp/azoth-foundation-benchmark.csv"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    if iterations == 0 {
        return Err("--iterations must be greater than zero".into());
    }
    if jobs == 0 {
        return Err("--jobs must be greater than zero".into());
    }
    let source_revision = source_revision.ok_or(
        "--source-revision is required so benchmark artifacts identify the evaluated source",
    )?;
    if source_revision.trim().is_empty() {
        return Err("--source-revision must not be empty".into());
    }
    checkpoints.sort_unstable();
    checkpoints.dedup();
    if checkpoints.is_empty() || checkpoints.contains(&0) {
        return Err("--checkpoints must contain positive values".into());
    }
    if checkpoints.iter().any(|value| *value > iterations) {
        return Err("every checkpoint must be <= --iterations".into());
    }

    Ok(Args {
        iterations,
        checkpoints,
        json_path: json_path.unwrap_or_else(|| {
            PathBuf::from(format!("/tmp/azoth-foundation-benchmark-{iterations}.json"))
        }),
        csv_path: csv_path.unwrap_or_else(|| {
            PathBuf::from(format!("/tmp/azoth-foundation-benchmark-{iterations}.csv"))
        }),
        determinism_checks: determinism_checks.unwrap_or(iterations),
        jobs: jobs.min(iterations),
        source_revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_difference_counts_hamming_and_length() {
        let (changed, percent) = positional_difference(b"abc", b"axc");
        assert_eq!(changed, 1);
        assert!((percent - 100.0 / 3.0).abs() < 1e-12);
        assert_eq!(positional_difference(b"abc", b"abcde"), (2, 40.0));
    }

    #[test]
    fn sequential_seeds_are_reproducible_and_distinct() {
        assert_eq!(sequential_seed(7).to_hex(), sequential_seed(7).to_hex());
        assert_ne!(sequential_seed(7).to_hex(), sequential_seed(8).to_hex());
        assert_eq!(
            sequential_seed(0).to_hex(),
            format!("0x{}", "00".repeat(32))
        );
        assert_eq!(
            sequential_seed(1).to_hex(),
            format!("0x{}01", "00".repeat(31))
        );
    }

    #[test]
    fn fixture_constructor_lengths_are_exact() {
        let erc20 = full_deployment_hex(FIXTURES[0]).unwrap();
        let native = full_deployment_hex(FIXTURES[1]).unwrap();
        assert_eq!(hex::decode(erc20).unwrap().len(), 8_969 + 160);
        assert_eq!(hex::decode(native).unwrap().len(), 7_758 + 128);
    }

    #[test]
    fn safe_profile_is_explicitly_pinned() {
        let profile = safe_profile(sequential_seed(0));
        assert!(profile.preserve_unknown_opcodes);
        assert!(!profile.rewrite_function_selectors);
        assert!(!profile.obfuscate_constructor_arguments);
        assert_eq!(profile.transforms.len(), 1);
        assert_eq!(profile.transforms[0].name(), "ClusterShuffle");
    }

    #[test]
    fn csv_rows_have_the_documented_column_count() {
        let mut output = String::new();
        append_csv_row(&mut output, &vec![String::new(); 36]).unwrap();
        assert_eq!(output.trim_end().split(',').count(), 36);
    }

    #[test]
    fn large_pairwise_sample_contains_ten_thousand_distinct_pairs() {
        let records: Vec<_> = (0..1_000)
            .map(|seed_index| SuccessRecord {
                seed_index,
                creation: seed_index.to_be_bytes().to_vec(),
                runtime: seed_index.to_be_bytes().to_vec(),
                creation_change_percent: 0.0,
                runtime_change_percent: 0.0,
                size_delta_bytes: 0,
                size_delta_percent: 0.0,
                runtime_size_delta_bytes: 0,
                runtime_size_delta_percent: 0.0,
                deployment_gas: 0,
                deployment_gas_delta_percent: 0.0,
                transforms: Vec::new(),
                mapping_fingerprint: None,
                replay: ReplayCheck::default(),
            })
            .collect();
        let references: Vec<_> = records.iter().collect();
        let summary = pairwise_diversity(&references, |record| &record.runtime);
        assert_eq!(summary["pairs"], 10_000);
        assert_eq!(
            summary["sampling"],
            "distinct_deterministic_splitmix64_sample"
        );
    }

    #[test]
    fn checkpoint_separates_exact_identity_from_changed_successes() {
        let original_creation = vec![0x60, 0x00];
        let original_runtime = vec![0x5b];
        let make_record = |seed_index, creation, runtime| SuccessRecord {
            seed_index,
            creation,
            runtime,
            creation_change_percent: 0.0,
            runtime_change_percent: 0.0,
            size_delta_bytes: 0,
            size_delta_percent: 0.0,
            runtime_size_delta_bytes: 0,
            runtime_size_delta_percent: 0.0,
            deployment_gas: 100,
            deployment_gas_delta_percent: 0.0,
            transforms: Vec::new(),
            mapping_fingerprint: None,
            replay: ReplayCheck::default(),
        };
        let successes = vec![
            make_record(0, original_creation.clone(), original_runtime.clone()),
            make_record(1, vec![0x60, 0x01], original_runtime.clone()),
            make_record(2, original_creation.clone(), vec![0x00]),
        ];

        let failures = vec![FailureRecord {
            seed_index: 3,
            message: "expected test failure".to_string(),
            replay: ReplayCheck::default(),
        }];
        let summary = summarize_checkpoint(
            4,
            &successes,
            &failures,
            &original_creation,
            &original_runtime,
            100,
        );

        assert_eq!(summary["successes"], 3);
        assert_eq!(summary["failures"], 1);
        assert_eq!(summary["exact_identity_outputs"], 1);
        assert_eq!(summary["changed_outputs"], 2);
        let changed_rate = summary["changed_output_rate_percent_of_successes"]
            .as_f64()
            .unwrap();
        assert!((changed_rate - 200.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn original_fixtures_deploy_and_keep_runtime_length() {
        for fixture in FIXTURES {
            let creation = hex::decode(full_deployment_hex(fixture).unwrap()).unwrap();
            let expected_runtime = hex::decode(normalized_hex(fixture.runtime)).unwrap();
            let (deployed_runtime, _) = deploy_creation(&creation).unwrap();
            assert_eq!(
                deployed_runtime.len(),
                expected_runtime.len(),
                "{} runtime length",
                fixture.name
            );
        }
    }
}
