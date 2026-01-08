//! Fuzz testing subcommand for the Azoth CLI.
//!
//! Runs parallel fuzz testing against the obfuscation pipeline, saving
//! reproducible crash inputs with debug traces for TUI visualization.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use azoth_core::cfg_ir::TraceEvent;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use clap::{Args, Subcommand};
use parking_lot::Mutex;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

use super::obfuscate::build_passes;
use crate::commands::DEFAULT_PASSES;

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// A writer that captures log output to a buffer.
/// Uses Arc<Mutex> because tracing's `with_default` requires Send + Sync.
/// parking_lot::Mutex is just a single atomic op for uncontended locks.
#[derive(Clone)]
struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn clear(&self) {
        self.buffer.lock().clear();
    }

    fn extract_lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.buffer.lock())
            .lines()
            .map(|s| s.to_string())
            .collect()
    }
}

impl Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// Contract bytecodes
const ESCROW_DEPLOYMENT: &str =
    include_str!("../../../../examples/escrow-bytecode/artifacts/deployment_bytecode.hex");
const ESCROW_RUNTIME: &str =
    include_str!("../../../../examples/escrow-bytecode/artifacts/runtime_bytecode.hex");
const COUNTER_DEPLOYMENT: &str =
    include_str!("../../../../tests/bytecode/counter/counter_deployment.hex");
const COUNTER_RUNTIME: &str =
    include_str!("../../../../tests/bytecode/counter/counter_runtime.hex");

/// Fuzz testing for the obfuscation pipeline.
#[derive(Args)]
pub struct FuzzArgs {
    #[command(subcommand)]
    command: Option<FuzzCommand>,

    /// Number of parallel fuzzing tasks (defaults to number of CPU cores)
    #[arg(short = 'j', long, default_value_t = num_cpus())]
    jobs: usize,

    /// Maximum iterations (0 = infinite)
    #[arg(short, long, default_value = "0")]
    iterations: u64,

    /// Duration in seconds (0 = infinite)
    #[arg(short, long, default_value = "0")]
    duration: u64,

    /// Directory to save crash inputs
    #[arg(long, default_value = "crashes")]
    crash_dir: PathBuf,

    /// Check that obfuscated bytecode deploys successfully
    #[arg(long, default_value = "false")]
    check_deploy: bool,
}

#[derive(Subcommand)]
enum FuzzCommand {
    /// Replay a saved crash file
    Replay {
        /// Path to crash JSON file
        crash_file: PathBuf,
    },
    /// List all saved crashes
    List,
}

/// Contract to fuzz test.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Contract {
    Escrow,
    Counter,
}

impl Contract {
    const ALL: [Self; 2] = [Self::Escrow, Self::Counter];

    fn name(self) -> &'static str {
        match self {
            Self::Escrow => "escrow",
            Self::Counter => "counter",
        }
    }

    fn deployment_hex(self) -> &'static str {
        match self {
            Self::Escrow => ESCROW_DEPLOYMENT,
            Self::Counter => COUNTER_DEPLOYMENT,
        }
    }

    fn runtime_hex(self) -> &'static str {
        match self {
            Self::Escrow => ESCROW_RUNTIME,
            Self::Counter => COUNTER_RUNTIME,
        }
    }
}

/// Generate a random comma-separated pass string from bits.
fn passes_from_bits(bits: u8) -> String {
    DEFAULT_PASSES
        .split(",")
        .enumerate()
        .filter(|(i, _)| bits & (1 << i) != 0)
        .map(|(_, name)| name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Reproducible fuzz input containing all parameters needed to replay a test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FuzzInput {
    contract: Contract,
    seed: String,
    passes: String,
}

impl FuzzInput {
    fn new(contract: Contract, seed_bytes: [u8; 32], passes: String) -> Self {
        Self {
            contract,
            seed: hex::encode(seed_bytes),
            passes,
        }
    }

    fn seed_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&self.seed) {
            if decoded.len() == 32 {
                bytes.copy_from_slice(&decoded);
            }
        }
        bytes
    }
}

/// Error categories for crash classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ErrorKind {
    Obfuscation,
    Validation,
    DeploymentMismatch { original: usize, obfuscated: usize },
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Obfuscation => write!(f, "obfuscation failed"),
            Self::Validation => write!(f, "validation failed"),
            Self::DeploymentMismatch {
                original,
                obfuscated,
            } => {
                write!(
                    f,
                    "deployment mismatch (orig={original}b, obf={obfuscated}b)"
                )
            }
        }
    }
}

/// Crash report saved to disk for reproduction and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrashReport {
    id: String,
    timestamp: String,
    input: FuzzInput,
    error_kind: ErrorKind,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfuscated_bytecode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_file: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    logs: Vec<String>,
}

/// Statistics tracked during fuzzing
struct FuzzStats {
    iterations: AtomicU64,
    successes: AtomicU64,
    errors: AtomicU64,
    deployment_mismatches: AtomicU64,
    unique_crashes: Mutex<HashSet<String>>,
    start_time: Instant,
}

impl FuzzStats {
    fn new() -> Self {
        Self {
            iterations: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            deployment_mismatches: AtomicU64::new(0),
            unique_crashes: Mutex::new(HashSet::new()),
            start_time: Instant::now(),
        }
    }

    fn print_summary(&self, check_deploy: bool) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let iters = self.iterations.load(Ordering::Relaxed);
        let rate = if elapsed > 0.0 {
            iters as f64 / elapsed
        } else {
            0.0
        };

        println!("\r\x1b[K=== Fuzzing Summary ===");
        println!("Duration: {:.1}s", elapsed);
        println!("Iterations: {}", iters);
        println!("Rate: {:.1} iter/sec", rate);
        println!("Successes: {}", self.successes.load(Ordering::Relaxed));
        println!("Errors: {}", self.errors.load(Ordering::Relaxed));
        if check_deploy {
            println!(
                "Deployment mismatches: {}",
                self.deployment_mismatches.load(Ordering::Relaxed)
            );
        }
        println!("Unique crashes saved: {}", self.unique_crashes.lock().len());
    }
}

const MOCK_TOKEN_ADDR: Address = Address::new([0x11; 20]);
const MOCK_RECIPIENT_ADDR: Address = Address::new([0x22; 20]);

fn prepare_escrow_bytecode(deployment_hex: &str) -> Option<Vec<u8>> {
    let normalized = deployment_hex.trim().trim_start_matches("0x");
    let mut bytecode = hex::decode(normalized).ok()?;
    bytecode.extend_from_slice(&[0; 12]);
    bytecode.extend_from_slice(MOCK_TOKEN_ADDR.as_slice());
    bytecode.extend_from_slice(&[0; 12]);
    bytecode.extend_from_slice(MOCK_RECIPIENT_ADDR.as_slice());
    bytecode.extend_from_slice(&[0; 32]);
    bytecode.extend_from_slice(&[0; 32]);
    bytecode.extend_from_slice(&[0; 32]);
    Some(bytecode)
}

fn prepare_counter_bytecode(deployment_hex: &str) -> Option<Vec<u8>> {
    let normalized = deployment_hex.trim().trim_start_matches("0x");
    hex::decode(normalized).ok()
}

fn prepare_bytecode(contract: Contract, deployment_hex: &str) -> Option<Vec<u8>> {
    match contract {
        Contract::Escrow => prepare_escrow_bytecode(deployment_hex),
        Contract::Counter => prepare_counter_bytecode(deployment_hex),
    }
}

fn deploy_to_revm(bytecode: &[u8], contract: Contract) -> Result<Address, String> {
    let mut db = InMemoryDB::default();
    let deployer = Address::from([0x42u8; 20]);

    db.insert_account_info(
        deployer,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );

    if contract == Contract::Escrow {
        db.insert_account_info(
            MOCK_TOKEN_ADDR,
            AccountInfo {
                balance: U256::ZERO,
                nonce: 1,
                code_hash: revm::primitives::KECCAK_EMPTY,
                code: Some(Bytecode::new_raw(Bytes::from_static(&[
                    0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
                ]))),
            },
        );
    }

    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: bytecode.to_vec().into(),
        value: U256::ZERO,
        ..Default::default()
    };

    let result = evm
        .transact(tx)
        .map_err(|e| format!("EVM error: {:?}", e))?;

    match result.result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(addr)),
            ..
        } => Ok(addr),
        ExecutionResult::Success { .. } => Err("No address returned".into()),
        ExecutionResult::Revert { output, .. } => Err(format!("Reverted: {:?}", output)),
        ExecutionResult::Halt { reason, .. } => Err(format!("Halted: {:?}", reason)),
    }
}

fn crash_hash(input: &FuzzInput, error: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{:?}", input.contract).as_bytes());
    hasher.update(input.passes.as_bytes());
    hasher.update(error.as_bytes());
    hex::encode(&hasher.finalize()[..8])
}

/// Failure from a fuzz run, containing error info and trace for debugging.
struct FuzzFailure {
    kind: ErrorKind,
    message: String,
    trace: Vec<TraceEvent>,
    obfuscated_bytecode: Option<String>,
    logs: Vec<String>,
}

fn save_crash(
    crash_dir: &PathBuf,
    input: &FuzzInput,
    failure: &FuzzFailure,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(crash_dir)?;

    let crash_id = crash_hash(input, &failure.message);

    // Save trace file if we have trace events
    let trace_file = if !failure.trace.is_empty() {
        let filename = format!("trace_{crash_id}.json");
        let path = crash_dir.join(&filename);
        fs::write(&path, serde_json::to_string_pretty(&failure.trace)?)?;
        Some(filename)
    } else {
        None
    };

    let report = CrashReport {
        id: crash_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        input: input.clone(),
        error_kind: failure.kind.clone(),
        message: failure.message.clone(),
        obfuscated_bytecode: failure.obfuscated_bytecode.clone(),
        trace_file,
        logs: failure.logs.clone(),
    };

    let path = crash_dir.join(format!("crash_{}.json", report.id));
    fs::write(&path, serde_json::to_string_pretty(&report)?)?;
    Ok(path)
}

async fn run_fuzz_input(input: &FuzzInput, check_deploy: bool) -> Result<(), FuzzFailure> {
    let deployment_hex = input.contract.deployment_hex();
    let runtime_hex = input.contract.runtime_hex();
    let seed = Seed::from_bytes(input.seed_bytes());

    let transforms = build_passes(&input.passes).map_err(|e| FuzzFailure {
        kind: ErrorKind::Obfuscation,
        message: format!("invalid passes: {e}"),
        trace: Vec::new(),
        obfuscated_bytecode: None,
        logs: Vec::new(),
    })?;

    let config = ObfuscationConfig {
        seed,
        transforms,
        preserve_unknown_opcodes: true,
    };

    let result = obfuscate_bytecode(deployment_hex, runtime_hex, config)
        .await
        .map_err(|e| {
            let kind = if e.message.contains("validation") || e.message.contains("invalid jump") {
                ErrorKind::Validation
            } else {
                ErrorKind::Obfuscation
            };
            FuzzFailure {
                kind,
                message: e.message,
                trace: e.trace,
                obfuscated_bytecode: None,
                logs: Vec::new(),
            }
        })?;

    if !check_deploy {
        return Ok(());
    }

    let original_bytes =
        prepare_bytecode(input.contract, deployment_hex).ok_or_else(|| FuzzFailure {
            kind: ErrorKind::Obfuscation,
            message: "failed to prepare original bytecode".into(),
            trace: result.trace.clone(),
            obfuscated_bytecode: Some(result.obfuscated_bytecode.clone()),
            logs: Vec::new(),
        })?;

    let original_deployed = deploy_to_revm(&original_bytes, input.contract).is_ok();

    let prepared_obfuscated = prepare_bytecode(input.contract, &result.obfuscated_bytecode)
        .ok_or_else(|| FuzzFailure {
            kind: ErrorKind::Obfuscation,
            message: "failed to prepare obfuscated bytecode".into(),
            trace: result.trace.clone(),
            obfuscated_bytecode: Some(result.obfuscated_bytecode.clone()),
            logs: Vec::new(),
        })?;

    let obfuscated_deployed = deploy_to_revm(&prepared_obfuscated, input.contract).is_ok();

    if original_deployed && !obfuscated_deployed {
        return Err(FuzzFailure {
            kind: ErrorKind::DeploymentMismatch {
                original: original_bytes.len(),
                obfuscated: prepared_obfuscated.len(),
            },
            message: format!(
                "original deployed but obfuscated failed ({}b vs {}b)",
                original_bytes.len(),
                prepared_obfuscated.len()
            ),
            trace: result.trace,
            obfuscated_bytecode: Some(result.obfuscated_bytecode),
            logs: Vec::new(),
        });
    }

    Ok(())
}

/// Runs a fuzz input using the provided log capture buffer.
/// Clears the buffer before running and extracts logs on failure.
async fn run_fuzz_input_capturing(
    input: &FuzzInput,
    log_capture: &LogCapture,
    check_deploy: bool,
) -> Result<(), FuzzFailure> {
    log_capture.clear();
    let result = run_fuzz_input(input, check_deploy).await;
    result.map_err(|mut failure| {
        failure.logs = log_capture.extract_lines();
        failure
    })
}

async fn replay_crash(crash_file: &PathBuf, check_deploy: bool) -> Result<(), Box<dyn Error>> {
    let content = fs::read_to_string(crash_file)?;
    let report: CrashReport = serde_json::from_str(&content)?;

    println!("=== Replaying Crash ===");
    println!("ID: {}", report.id);
    println!("Timestamp: {}", report.timestamp);
    println!("Contract: {:?}", report.input.contract);
    println!("Seed: {}", report.input.seed);
    println!(
        "Passes: {}",
        if report.input.passes.is_empty() {
            "none"
        } else {
            &report.input.passes
        }
    );
    println!("Original error: {}", report.message);
    if let Some(ref trace) = report.trace_file {
        println!("Debug trace: {trace}");
    }
    if !report.logs.is_empty() {
        println!("Captured logs: {} lines", report.logs.len());
    }
    println!();

    if !report.logs.is_empty() {
        println!("=== Captured Logs ===");
        for line in &report.logs {
            println!("{line}");
        }
        println!();
    }

    println!("Running...");

    let log_capture = LogCapture::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(log_capture.clone())
            .with_ansi(false)
            .without_time(),
    );
    let dispatch = tracing::dispatcher::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let result = run_fuzz_input_capturing(&report.input, &log_capture, check_deploy).await;

    match result {
        Ok(()) => println!("SUCCESS - No error reproduced!"),
        Err(failure) => {
            println!("REPRODUCED!");
            println!("Error: {}", failure.kind);
            println!("Message: {}", failure.message);
            if !failure.logs.is_empty() {
                println!();
                println!("=== New Logs ===");
                for line in &failure.logs {
                    println!("{line}");
                }
            }
        }
    }

    Ok(())
}

fn list_crashes(crash_dir: &PathBuf) -> Result<(), Box<dyn Error>> {
    if !crash_dir.exists() {
        println!("No crashes directory found at {crash_dir:?}");
        return Ok(());
    }

    let mut crashes = Vec::new();
    for entry in fs::read_dir(crash_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("crash_"))
        {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(report) = serde_json::from_str::<CrashReport>(&content) {
                    crashes.push((path, report));
                }
            }
        }
    }

    if crashes.is_empty() {
        println!("No crashes found in {crash_dir:?}");
        return Ok(());
    }

    println!("=== Saved Crashes ({}) ===\n", crashes.len());
    for (path, report) in crashes {
        println!("File: {}", path.display());
        println!("  ID: {}", report.id);
        println!("  Contract: {:?}", report.input.contract);
        println!(
            "  Passes: {}",
            if report.input.passes.is_empty() {
                "none"
            } else {
                &report.input.passes
            }
        );
        println!("  Error: {}", report.error_kind);
        if report.trace_file.is_some() {
            println!("  Trace: available");
        }
        if !report.logs.is_empty() {
            println!("  Logs: {} lines", report.logs.len());
        }
        println!();
    }

    Ok(())
}

async fn fuzzer_worker(
    worker_id: usize,
    stats: Arc<FuzzStats>,
    args: Arc<FuzzArgs>,
    crash_dir: PathBuf,
) {
    let log_capture = LogCapture::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(log_capture.clone())
            .with_ansi(false)
            .without_time(),
    );
    let dispatch = tracing::dispatcher::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

    let mut rng = SmallRng::seed_from_u64(worker_id as u64 ^ 0xdeadbeef);

    loop {
        let iters = stats.iterations.fetch_add(1, Ordering::Relaxed);
        if args.iterations > 0 && iters >= args.iterations {
            break;
        }
        if args.duration > 0 && stats.start_time.elapsed().as_secs() >= args.duration {
            break;
        }

        let contract = Contract::ALL[(rng.next_u32() as usize) % Contract::ALL.len()];
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        let passes = passes_from_bits((rng.next_u32() % 8) as u8);

        let input = FuzzInput::new(contract, seed_bytes, passes);

        match run_fuzz_input_capturing(&input, &log_capture, args.check_deploy).await {
            Ok(()) => {
                stats.successes.fetch_add(1, Ordering::Relaxed);
            }
            Err(failure) => {
                let is_mismatch = matches!(failure.kind, ErrorKind::DeploymentMismatch { .. });
                let is_interesting = is_mismatch || matches!(failure.kind, ErrorKind::Validation);

                if is_mismatch {
                    stats.deployment_mismatches.fetch_add(1, Ordering::Relaxed);
                }
                stats.errors.fetch_add(1, Ordering::Relaxed);

                if is_interesting {
                    let crash_id = crash_hash(&input, &failure.message);
                    let mut crashes = stats.unique_crashes.lock();

                    if crashes.insert(crash_id.clone()) {
                        if let Ok(path) = save_crash(&crash_dir, &input, &failure) {
                            let passes_display = if input.passes.is_empty() {
                                "none"
                            } else {
                                &input.passes
                            };
                            eprintln!("\n[CRASH] Saved: {}", path.display());
                            eprintln!(
                                "  {:?} | {} | {}",
                                input.contract, passes_display, failure.kind
                            );
                        }
                    }
                }
            }
        }
    }
}

fn status_printer(stats: Arc<FuzzStats>, stop: Arc<std::sync::atomic::AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let elapsed = stats.start_time.elapsed();
        let secs = elapsed.as_secs();
        let iters = stats.iterations.load(Ordering::Relaxed);
        let rate = if elapsed.as_secs_f64() > 0.0 {
            iters as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let ok = stats.successes.load(Ordering::Relaxed);
        let mismatch = stats.deployment_mismatches.load(Ordering::Relaxed);
        let crashes = stats.unique_crashes.lock().len();
        print!(
            "\r\x1b[K[{:02}:{:02}] {:.1}/s iter={} ok={} mismatch={} crashes={}",
            secs / 60,
            secs % 60,
            rate,
            iters,
            ok,
            mismatch,
            crashes
        );
        std::io::stdout().flush().ok();
    }
}

#[async_trait]
impl super::Command for FuzzArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        match &self.command {
            Some(FuzzCommand::Replay { crash_file }) => {
                return replay_crash(crash_file, self.check_deploy).await;
            }
            Some(FuzzCommand::List) => {
                return list_crashes(&self.crash_dir);
            }
            None => {}
        }

        println!("Azoth Fuzzer");
        println!("============");
        println!("Jobs: {}", self.jobs);
        println!(
            "Iterations: {}",
            if self.iterations == 0 {
                "infinite".to_string()
            } else {
                self.iterations.to_string()
            }
        );
        println!(
            "Duration: {}",
            if self.duration == 0 {
                "infinite".to_string()
            } else {
                format!("{}s", self.duration)
            }
        );
        println!("Crash dir: {}", self.crash_dir.display());
        let contracts: Vec<_> = Contract::ALL.iter().map(|c| c.name()).collect();
        println!("Contracts: {}", contracts.join(", "));
        println!("Transforms: none, {}", DEFAULT_PASSES);
        println!();

        let args = Arc::new(self);
        let stats = Arc::new(FuzzStats::new());
        let crash_dir = args.crash_dir.clone();

        // Spawn status printer on dedicated thread
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let status_thread = {
            let stats = stats.clone();
            let stop = stop.clone();
            std::thread::spawn(move || status_printer(stats, stop))
        };

        let mut handles = Vec::new();
        for worker_id in 0..args.jobs {
            let stats = stats.clone();
            let args = args.clone();
            let crash_dir = crash_dir.clone();

            handles.push(tokio::spawn(fuzzer_worker(
                worker_id, stats, args, crash_dir,
            )));
        }

        for handle in handles {
            let _ = handle.await;
        }

        // Stop status printer and print summary
        stop.store(true, Ordering::Relaxed);
        let _ = status_thread.join();
        stats.print_summary(args.check_deploy);
        Ok(())
    }
}
