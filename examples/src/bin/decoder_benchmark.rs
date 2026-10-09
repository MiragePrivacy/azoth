//! Reproducible release-mode benchmark for Azoth's native bytecode decoder.
//!
//! The output is one JSON document. Decoding and assembly rendering are timed separately because
//! production CFG consumers do not need the human-readable assembly string.

use azoth_core::decoder::{decode_executable_bytes, format_assembly, Instruction};
use serde_json::{json, Value};
use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant};

type BenchmarkResult<T> = Result<T, Box<dyn Error>>;
type BytecodeParts<'a> = (&'a [u8], &'a [u8]);

const STORAGE: &str = include_str!("../../../tests/bytecode/storage.hex");
const COUNTER_RUNTIME: &str = include_str!("../../../tests/bytecode/counter/counter_runtime.hex");
const NATIVE_ESCROW_RUNTIME: &str =
    include_str!("../../escrow-bytecode/artifacts/native_runtime.hex");
const ERC20_ESCROW_RUNTIME: &str =
    include_str!("../../escrow-bytecode/artifacts/erc20_runtime.hex");
const ITERATION_CHECKPOINTS: [usize; 3] = [10, 100, 1_000];
const WARMUP_ITERATIONS: usize = 10;

#[derive(Clone, Copy)]
struct Fixture {
    name: &'static str,
    source: &'static str,
}

const FIXTURES: [Fixture; 4] = [
    Fixture {
        name: "storage",
        source: STORAGE,
    },
    Fixture {
        name: "counter_runtime",
        source: COUNTER_RUNTIME,
    },
    Fixture {
        name: "escrow_native_runtime",
        source: NATIVE_ESCROW_RUNTIME,
    },
    Fixture {
        name: "escrow_erc20_runtime",
        source: ERC20_ESCROW_RUNTIME,
    },
];

fn main() -> BenchmarkResult<()> {
    let mut measurements = Vec::new();

    for fixture in FIXTURES {
        let artifact = hex::decode(fixture.source.trim().trim_start_matches("0x"))?;
        let (code, trailer) = split_compiler_trailer(&artifact)?;
        let instructions = decode_executable_bytes(code)?;

        // Warm both paths before taking any sample. Keep the warmup outside every timed region.
        for _ in 0..WARMUP_ITERATIONS {
            drop(black_box(decode_executable_bytes(black_box(code))?));
            drop(black_box(format_assembly(black_box(&instructions))));
        }

        for iterations in ITERATION_CHECKPOINTS {
            measurements.push(measure_decode(
                fixture.name,
                code,
                trailer.len(),
                instructions.len(),
                iterations,
            )?);
            measurements.push(measure_render(
                fixture.name,
                code.len(),
                trailer.len(),
                &instructions,
                iterations,
            ));
        }
    }

    let report = json!({
        "schema": "azoth-native-decoder-benchmark-v1",
        "profile": "release-mode wall clock; fixed checked-in fixtures; single thread",
        "warmup_iterations": WARMUP_ITERATIONS,
        "iteration_checkpoints": ITERATION_CHECKPOINTS,
        "measurements": measurements,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn split_compiler_trailer(input: &[u8]) -> BenchmarkResult<BytecodeParts<'_>> {
    let encoded_len = input
        .get(input.len().saturating_sub(2)..)
        .ok_or("fixture is too short for a compiler trailer length")?;
    let payload_len = usize::from(u16::from_be_bytes([encoded_len[0], encoded_len[1]]));
    let trailer_len = payload_len
        .checked_add(2)
        .ok_or("compiler trailer length overflow")?;
    let split = input
        .len()
        .checked_sub(trailer_len)
        .ok_or("compiler trailer exceeds fixture length")?;
    Ok(input.split_at(split))
}

fn measure_decode(
    fixture: &str,
    code: &[u8],
    trailer_bytes: usize,
    instructions_per_iteration: usize,
    iterations: usize,
) -> Result<Value, azoth_core::Error> {
    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        let instructions = decode_executable_bytes(black_box(code))?;
        checksum = checksum.wrapping_add(instructions.len());
        black_box(instructions);
    }
    let elapsed = started.elapsed();
    black_box(checksum);

    Ok(measurement(
        fixture,
        "decode",
        iterations,
        code.len(),
        trailer_bytes,
        instructions_per_iteration,
        None,
        elapsed,
        checksum,
    ))
}

fn measure_render(
    fixture: &str,
    code_bytes: usize,
    trailer_bytes: usize,
    instructions: &[Instruction],
    iterations: usize,
) -> Value {
    let representative = format_assembly(instructions);
    let assembly_bytes = representative.len();
    black_box(representative);

    let started = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iterations {
        let assembly = format_assembly(black_box(instructions));
        checksum = checksum.wrapping_add(assembly.len());
        black_box(assembly);
    }
    let elapsed = started.elapsed();
    black_box(checksum);

    measurement(
        fixture,
        "format_assembly",
        iterations,
        code_bytes,
        trailer_bytes,
        instructions.len(),
        Some(assembly_bytes),
        elapsed,
        checksum,
    )
}

#[allow(clippy::too_many_arguments)]
fn measurement(
    fixture: &str,
    phase: &str,
    iterations: usize,
    code_bytes: usize,
    trailer_bytes: usize,
    instructions_per_iteration: usize,
    assembly_bytes_per_iteration: Option<usize>,
    elapsed: Duration,
    checksum: usize,
) -> Value {
    let elapsed_ns = elapsed.as_nanos();
    let bytes_processed = code_bytes.saturating_mul(iterations);
    let seconds = elapsed.as_secs_f64();
    let mib_per_second = if seconds == 0.0 {
        0.0
    } else {
        bytes_processed as f64 / (1024.0 * 1024.0) / seconds
    };

    json!({
        "fixture": fixture,
        "phase": phase,
        "iterations": iterations,
        "code_bytes_per_iteration": code_bytes,
        "compiler_trailer_bytes_excluded": trailer_bytes,
        "instructions_per_iteration": instructions_per_iteration,
        "assembly_bytes_per_iteration": assembly_bytes_per_iteration,
        "elapsed_ns": elapsed_ns,
        "mean_ns_per_iteration": elapsed_ns / iterations as u128,
        "code_mib_per_second": mib_per_second,
        "checksum": checksum,
    })
}
