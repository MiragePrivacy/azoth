//! Constructor-argument payload obfuscation.
//!
//! This pass masks the exact constructor-argument suffix identified from the caller-supplied
//! runtime and injects seed-derived, straight-line decoding code immediately after the init
//! code copies that suffix into memory. It does not inspect an ABI or contract source. The
//! masking is intentionally described as obfuscation rather than encryption: every value needed
//! to decode the arguments remains in public creation bytecode and can be recovered by a capable
//! symbolic or dynamic analyst.

use crate::arithmetic_chain::{compile_chain_inline, generate_chain, ChainConfig, ScatterStrategy};
use crate::{Error, Result};
use azoth_core::seed::{DeterministicRng, Seed};
use azoth_core::strip::CleanReport;
use azoth_core::{encoder, Opcode};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};

/// Measurements from constructor-argument obfuscation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConstructorArgsObfuscation {
    /// Whether a constructor-argument suffix was present and transformed.
    pub applied: bool,
    /// Number of constructor-argument bytes masked in the creation payload.
    pub argument_bytes: usize,
    /// Number of decoder bytes inserted into init code.
    pub decoder_bytes: usize,
    /// Number of 32-byte memory chunks decoded during construction.
    pub chunks: usize,
}

#[derive(Clone, Copy, Debug)]
struct InitOp {
    pc: usize,
    opcode: u8,
    value: Option<usize>,
}

/// Obfuscates an exactly located constructor-argument suffix and injects its decoder.
///
/// The function fails closed when constructor arguments exist but the init code does not expose
/// a supported, unambiguous `CODESIZE - creation_length` copy site. Returning the original
/// plaintext suffix in that situation would violate the caller's expectation that the pass was
/// applied.
pub fn obfuscate_constructor_args(
    report: &mut CleanReport,
    seed: &[u8; 32],
) -> Result<ConstructorArgsObfuscation> {
    let Some(args_index) = report.removed.iter().position(|removed| {
        matches!(
            removed.kind,
            azoth_core::detection::SectionKind::ConstructorArgs
        )
    }) else {
        return Ok(ConstructorArgsObfuscation::default());
    };
    let Some(init_index) = report
        .removed
        .iter()
        .position(|removed| matches!(removed.kind, azoth_core::detection::SectionKind::Init))
    else {
        return Err(Error::Generic(
            "constructor arguments were detected without init code".into(),
        ));
    };

    let argument_bytes = report.removed[args_index].data.len();
    if argument_bytes == 0 {
        return Ok(ConstructorArgsObfuscation::default());
    }

    let runtime_offset = report
        .runtime_layout
        .iter()
        .map(|span| span.offset)
        .min()
        .ok_or_else(|| Error::Generic("constructor arguments require a runtime section".into()))?;
    let deployed_suffix_len: usize = report
        .removed
        .iter()
        .filter(|removed| {
            removed.offset >= runtime_offset
                && !matches!(
                    removed.kind,
                    azoth_core::detection::SectionKind::ConstructorArgs
                )
        })
        .map(|removed| removed.data.len())
        .sum();
    let creation_len = runtime_offset + report.clean_len + deployed_suffix_len;

    let original_init = report.removed[init_index].data.to_vec();
    let (copy_pc, destination_depth, block_end) = find_argument_copy(&original_init, creation_len)?;

    let mut rng_domain = b"AZOTH_CONSTRUCTOR_ARGUMENTS_V2".to_vec();
    rng_domain.extend_from_slice(&(argument_bytes as u64).to_be_bytes());
    let mut rng = Seed::from_bytes(*seed).derive_rng(&rng_domain);

    let original_args = report.removed[args_index].data.to_vec();
    let chunks = argument_bytes.div_ceil(32);
    let mut masked_args = original_args.clone();
    let mut masks = Vec::with_capacity(chunks);
    for chunk_index in 0..chunks {
        let start = chunk_index * 32;
        let used = (argument_bytes - start).min(32);
        let mut mask = [0u8; 32];
        rng.fill_bytes(&mut mask[..used]);
        if mask[..used].iter().all(|byte| *byte == 0) {
            mask[0] = 1;
        }
        for index in 0..used {
            masked_args[start + index] ^= mask[index];
        }
        masks.push(mask);
    }

    let mut order: Vec<usize> = (0..chunks).collect();
    order.shuffle(&mut rng);
    let mut decode_body = Vec::new();
    for chunk_index in order {
        emit_chunk_decoder(
            &mut decode_body,
            destination_depth,
            chunk_index * 32,
            masks[chunk_index],
            &mut rng,
        )?;
    }

    let replay_tail = original_init[copy_pc + 1..block_end].to_vec();
    let mut rewritten_init = original_init;
    let trampoline_pc = copy_pc - 1;
    let decoder_pc = rewritten_init.len();
    if decoder_pc > u16::MAX as usize {
        return Err(Error::Generic(format!(
            "constructor decoder target 0x{decoder_pc:x} exceeds PUSH2 capacity"
        )));
    }
    if block_end <= copy_pc + 1 || trampoline_pc + 4 > block_end {
        return Err(Error::Generic(
            "constructor argument copy block is too short for an in-place trampoline".into(),
        ));
    }

    // The seed-varied trampoline overwrites bytes in the current basic block without moving any
    // existing init PC. The appended decoder replays the whole original block tail after
    // decoding, so every pre-existing jump target remains unchanged.
    let trampoline = make_trampoline(
        trampoline_pc,
        decoder_pc,
        block_end - trampoline_pc,
        &mut rng,
    )?;
    rewritten_init[trampoline_pc..trampoline_pc + trampoline.len()].copy_from_slice(&trampoline);

    let duplicated_opcode = 0x7f + (destination_depth + 2) as u8;
    let mut decoder = Vec::with_capacity(7 + decode_body.len() + block_end - copy_pc);
    decoder.push(Opcode::JUMPDEST.to_byte());
    emit_stack_neutral_noise(&mut decoder, &mut rng);
    decoder.push(duplicated_opcode);
    emit_stack_neutral_noise(&mut decoder, &mut rng);
    decoder.push(Opcode::CODECOPY.to_byte());
    decoder.extend_from_slice(&decode_body);
    decoder.extend_from_slice(&replay_tail);
    rewritten_init.extend_from_slice(&decoder);

    report.removed[init_index].data = rewritten_init.into();
    report.removed[args_index].data = masked_args.into();

    Ok(ConstructorArgsObfuscation {
        applied: true,
        argument_bytes,
        decoder_bytes: decoder.len(),
        chunks,
    })
}

fn emit_stack_neutral_noise(out: &mut Vec<u8>, rng: &mut DeterministicRng) {
    match rng.random_range(0..4) {
        0 => {}
        1 => {
            out.push(Opcode::PUSH0.to_byte());
            out.push(Opcode::POP.to_byte());
        }
        2 => {
            out.push(Opcode::PC.to_byte());
            out.push(Opcode::POP.to_byte());
        }
        3 => {
            out.push(Opcode::PUSH(1).to_byte());
            out.push(rng.random());
            out.push(Opcode::POP.to_byte());
        }
        _ => unreachable!(),
    }
}

fn decode_init(bytes: &[u8]) -> Result<Vec<InitOp>> {
    let mut ops = Vec::new();
    let mut pc = 0usize;
    while pc < bytes.len() {
        let opcode = bytes[pc];
        let width = if (0x60..=0x7f).contains(&opcode) {
            (opcode - 0x5f) as usize
        } else {
            0
        };
        let end = pc + 1 + width;
        if end > bytes.len() {
            return Err(Error::Generic(format!(
                "truncated PUSH{width} in init code at 0x{pc:x}"
            )));
        }
        let value = (width > 0).then(|| {
            bytes[pc + 1..end]
                .iter()
                .fold(0usize, |acc, &byte| (acc << 8) | byte as usize)
        });
        ops.push(InitOp { pc, opcode, value });
        pc = end;
    }
    Ok(ops)
}

fn find_argument_copy(init: &[u8], creation_len: usize) -> Result<(usize, usize, usize)> {
    let ops = decode_init(init)?;
    let mut candidates = Vec::new();

    for (index, op) in ops.iter().enumerate() {
        if op.value != Some(creation_len)
            || ops.get(index + 1).map(|next| next.opcode) != Some(0x80)
            || ops.get(index + 2).map(|next| next.opcode) != Some(0x38)
            || ops.get(index + 3).map(|next| next.opcode) != Some(0x03)
        {
            continue;
        }

        let Some((copy_index, copy)) = ops
            .iter()
            .enumerate()
            .skip(index + 4)
            .find(|(_, candidate)| candidate.opcode == 0x39)
        else {
            continue;
        };
        let Some(previous) = copy_index.checked_sub(1).and_then(|i| ops.get(i)) else {
            continue;
        };
        if !(0x82..=0x8f).contains(&previous.opcode) {
            continue;
        }
        let duplicated_depth = (previous.opcode - 0x7f) as usize;
        let destination_depth_after_copy = duplicated_depth - 2;
        if destination_depth_after_copy == 0 || destination_depth_after_copy > 16 {
            continue;
        }
        let Some(block_end) = ops
            .iter()
            .skip(copy_index + 1)
            .find(|candidate| candidate.opcode == 0x5b)
            .map(|candidate| candidate.pc)
        else {
            continue;
        };
        if ops[copy_index + 1..]
            .iter()
            .take_while(|candidate| candidate.pc < block_end)
            .any(|candidate| {
                matches!(
                    candidate.opcode,
                    opcode if opcode == Opcode::PC.to_byte()
                        || opcode == Opcode::CODESIZE.to_byte()
                        || opcode == Opcode::CODECOPY.to_byte()
                )
            })
        {
            continue;
        }
        candidates.push((copy.pc, destination_depth_after_copy, block_end));
    }

    if candidates.len() != 1 {
        return Err(Error::Generic(format!(
            "expected one constructor argument CODECOPY for creation length 0x{creation_len:x}, found {}",
            candidates.len()
        )));
    }
    Ok(candidates[0])
}

fn emit_chunk_decoder(
    out: &mut Vec<u8>,
    destination_depth: usize,
    offset: usize,
    mask: [u8; 32],
    rng: &mut DeterministicRng,
) -> Result<()> {
    let offset_first = offset > 0 && destination_depth < 16 && rng.random::<bool>();
    if offset_first {
        emit_push_usize(out, offset);
        emit_dup(out, destination_depth + 1)?;
        out.push(Opcode::ADD.to_byte());
    } else {
        emit_dup(out, destination_depth)?;
        if offset > 0 {
            emit_push_usize(out, offset);
            out.push(Opcode::ADD.to_byte());
        }
    }
    out.push(Opcode::DUP(1).to_byte());
    out.push(Opcode::MLOAD.to_byte());

    let chain = generate_chain(
        mask,
        &ChainConfig {
            chain_depth: 1..=3,
            inline_ratio: 1.0,
            ..Default::default()
        },
        rng,
    );
    let mut chain = chain;
    chain.scatter_locations = vec![ScatterStrategy::Inline; chain.initial_values.len()];
    let mut instructions = compile_chain_inline(&chain);
    // The chain compiler returns a relocatable fragment. Canonicalize its local PCs before
    // passing it across the encoder boundary, which deliberately rejects ambiguous IR.
    let mut next_pc = 0usize;
    for instruction in &mut instructions {
        instruction.pc = next_pc;
        next_pc = next_pc
            .checked_add(instruction.byte_size())
            .ok_or_else(|| {
                Error::EncodingError("constructor argument decoder is too large".into())
            })?;
    }
    let encoded = encoder::encode(&instructions, &[])
        .map_err(|error| Error::EncodingError(error.to_string()))?;
    out.extend_from_slice(&encoded);
    out.push(Opcode::XOR.to_byte());
    out.push(Opcode::SWAP(1).to_byte());
    out.push(Opcode::MSTORE.to_byte());
    Ok(())
}

fn make_trampoline(
    pc: usize,
    target: usize,
    available: usize,
    rng: &mut DeterministicRng,
) -> Result<Vec<u8>> {
    let mut variants = Vec::new();
    if target <= u16::MAX as usize && available >= 4 {
        variants.push(0u8); // direct PUSH2
    }
    if target <= 0x00ff_ffff && available >= 5 {
        variants.push(1u8); // direct PUSH3
    }
    if target >= pc && target - pc <= u16::MAX as usize && available >= 6 {
        variants.push(2u8); // PC-relative ADD
    }
    if target <= u16::MAX as usize && available >= 8 {
        variants.push(3u8); // split XOR
        variants.push(4u8); // split SUB
    }
    if variants.is_empty() {
        return Err(Error::Generic(
            "constructor argument copy block cannot hold a decoder trampoline".into(),
        ));
    }
    let variant = variants[rng.random_range(0..variants.len())];

    let mut out = Vec::new();
    match variant {
        0 => emit_push_width(&mut out, target, 2),
        1 => emit_push_width(&mut out, target, 3),
        2 => {
            out.push(Opcode::PC.to_byte());
            emit_push_width(&mut out, target - pc, 2);
            out.push(Opcode::ADD.to_byte());
        }
        3 => {
            let lhs = rng.random::<u16>() as usize;
            emit_push_width(&mut out, lhs, 2);
            emit_push_width(&mut out, lhs ^ target, 2);
            out.push(Opcode::XOR.to_byte());
        }
        4 => {
            let max_salt = u16::MAX as usize - target;
            let salt = rng.random_range(0..=max_salt);
            emit_push_width(&mut out, salt, 2);
            emit_push_width(&mut out, target + salt, 2);
            out.push(Opcode::SUB.to_byte());
        }
        _ => unreachable!(),
    }
    out.push(Opcode::JUMP.to_byte());
    Ok(out)
}

fn emit_push_width(out: &mut Vec<u8>, value: usize, width: usize) {
    out.push(Opcode::PUSH(width as u8).to_byte());
    for index in 0..width {
        let shift = (width - 1 - index) * 8;
        out.push(((value >> shift) & 0xff) as u8);
    }
}

fn emit_dup(out: &mut Vec<u8>, depth: usize) -> Result<()> {
    if !(1..=16).contains(&depth) {
        return Err(Error::StackOverflow);
    }
    out.push(Opcode::DUP(depth as u8).to_byte());
    Ok(())
}

fn emit_push_usize(out: &mut Vec<u8>, value: usize) {
    if value == 0 {
        out.push(Opcode::PUSH0.to_byte());
        return;
    }
    let width = ((usize::BITS - value.leading_zeros()) as usize).div_ceil(8);
    out.push(Opcode::PUSH(width as u8).to_byte());
    for index in 0..width {
        let shift = (width - 1 - index) * 8;
        out.push(((value >> shift) & 0xff) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
    use azoth_core::detection::locate_sections;
    use azoth_core::seed::Seed;
    use azoth_core::strip::{strip_bytecode, CleanReport};
    use rand::{RngCore, SeedableRng};
    use revm::bytecode::Bytecode;
    use revm::context::result::{ExecutionResult, Output};
    use revm::context::TxEnv;
    use revm::database::InMemoryDB;
    use revm::primitives::{Address, Bytes, TxKind, U256};
    use revm::state::AccountInfo;
    use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
    use std::time::Instant;

    const ESCROW_DEPLOYMENT: &str =
        include_str!("../../../examples/escrow-bytecode/artifacts/erc20_deployment.hex");
    const ESCROW_RUNTIME: &str =
        include_str!("../../../examples/escrow-bytecode/artifacts/erc20_runtime.hex");
    // A compact, non-GAS constructor fixture. It copies the constructor suffix to memory 0x80,
    // then deploys a fixed runtime. Both copies satisfy the production provenance contract; the
    // constructor mask is nevertheless rejected because injecting its decoder would relocate the
    // constructor's CODESIZE expression.
    const SUPPORTED_RUNTIME: &str = "0x602a5f5260205ff3";
    const SUPPORTED_DEPLOYMENT: &str =
        "0x608061002380380390823950600f565b600861001b5f3960085ff3602a5f5260205ff3";
    const MOCK_TOKEN: Address = Address::new([0x11; 20]);

    fn argument_words(recipient: [u8; 20], amount: [u8; 32], payment: [u8; 32]) -> Vec<u8> {
        let mut args = Vec::with_capacity(160);
        args.extend_from_slice(&[0; 12]);
        args.extend_from_slice(MOCK_TOKEN.as_slice());
        args.extend_from_slice(&[0; 12]);
        args.extend_from_slice(&recipient);
        args.extend_from_slice(&amount);
        args.extend_from_slice(&[0; 32]);
        args.extend_from_slice(&payment);
        args
    }

    fn escrow_creation_with_args(args: &[u8]) -> Vec<u8> {
        let mut deployment =
            hex::decode(ESCROW_DEPLOYMENT.trim().trim_start_matches("0x")).unwrap();
        deployment.extend_from_slice(args);
        deployment
    }

    fn supported_creation_with_args(args: &[u8]) -> Vec<u8> {
        let mut deployment =
            hex::decode(SUPPORTED_DEPLOYMENT.trim().trim_start_matches("0x")).unwrap();
        deployment.extend_from_slice(args);
        deployment
    }

    fn mask_report(
        deployment: &[u8],
        seed: &Seed,
    ) -> (Vec<u8>, CleanReport, ConstructorArgsObfuscation) {
        let runtime = hex::decode(SUPPORTED_RUNTIME.trim().trim_start_matches("0x")).unwrap();
        let sections = locate_sections(deployment, &[], &runtime).unwrap();
        let (clean, mut report) = strip_bytecode(deployment, &sections).unwrap();
        let metrics = obfuscate_constructor_args(&mut report, seed.as_bytes()).unwrap();
        (clean, report, metrics)
    }

    fn masked_arguments(report: &CleanReport) -> Vec<u8> {
        report
            .removed
            .iter()
            .find(|removed| removed.kind == azoth_core::detection::SectionKind::ConstructorArgs)
            .expect("fixture has constructor arguments")
            .data
            .to_vec()
    }

    fn deploy(bytecode: &[u8]) -> (Bytes, u64) {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            MOCK_TOKEN,
            AccountInfo {
                balance: U256::ZERO,
                nonce: 1,
                code_hash: revm::primitives::KECCAK_EMPTY,
                code: Some(Bytecode::new_raw(Bytes::from_static(&[
                    0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
                ]))),
            },
        );
        let deployer = Address::from([0x42; 20]);
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
        let result = evm
            .transact(TxEnv {
                caller: deployer,
                gas_limit: 30_000_000,
                kind: TxKind::Create,
                data: bytecode.to_vec().into(),
                value: U256::ZERO,
                ..Default::default()
            })
            .unwrap();
        match result.result {
            ExecutionResult::Success {
                output: Output::Create(runtime, Some(_)),
                gas_used,
                ..
            } => (runtime, gas_used),
            other => panic!("deployment failed: {other:?}"),
        }
    }

    #[test]
    fn push_encoder_uses_minimal_width() {
        let mut encoded = Vec::new();
        emit_push_usize(&mut encoded, 0x1234);
        assert_eq!(encoded, vec![0x61, 0x12, 0x34]);
    }

    #[test]
    fn decoder_rejects_ambiguous_copy_sites() {
        let error = find_argument_copy(&[0x60, 0x01, 0x00], 1).unwrap_err();
        assert!(error.to_string().contains("found 0"));
    }

    #[test]
    fn constructor_mask_generation_is_deterministic_but_reassembly_fails_closed() {
        let args = argument_words([0x22; 20], [0; 32], [0; 32]);
        let original = supported_creation_with_args(&args);
        let seed = Seed::from_bytes([0x55; 32]);
        let (clean, mut report, metrics) = mask_report(&original, &seed);
        let masked = masked_arguments(&report);

        assert!(metrics.applied);
        assert_eq!(metrics.argument_bytes, args.len());
        assert!(metrics.decoder_bytes > 0);
        assert_ne!(masked, args, "the ABI suffix must not survive verbatim");
        assert!(!masked.windows(5).any(|window| window == b"AZOTH"));
        let error = report.reassemble_checked(&clean).unwrap_err();
        assert!(error.contains("observes CODESIZE"), "{error}");

        let (_, repeat_report, _) = mask_report(&original, &seed);
        assert_eq!(
            masked,
            masked_arguments(&repeat_report),
            "same seed must be deterministic"
        );
        let (_, different_report, _) = mask_report(&original, &Seed::from_bytes([0x56; 32]));
        let different = masked_arguments(&different_report);
        assert_ne!(masked, different, "different seeds must vary the payload");
    }

    #[test]
    fn fuzzed_constructor_masks_fail_closed_during_reassembly() {
        let mut rng = DeterministicRng::seed_from_u64(0xA207_2026);
        for case in 0..64u64 {
            let mut recipient = [0u8; 20];
            let mut amount = [0u8; 32];
            let mut payment = [0u8; 32];
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut recipient);
            rng.fill_bytes(&mut amount);
            rng.fill_bytes(&mut payment);
            rng.fill_bytes(&mut seed);

            let mut args = argument_words(recipient, amount, payment);
            // Exercise decoder scaling and partial final words. Case zero uses the report-sized
            // 704-byte suffix; the remaining cases cover arbitrary trailing lengths.
            let trailing_len = if case == 0 {
                704 - args.len()
            } else {
                rng.random_range(0..=544)
            };
            let mut trailing = vec![0u8; trailing_len];
            rng.fill_bytes(&mut trailing);
            args.extend_from_slice(&trailing);
            let original = supported_creation_with_args(&args);
            let (clean, mut report, metrics) = mask_report(&original, &Seed::from_bytes(seed));
            let masked = masked_arguments(&report);
            assert!(metrics.applied, "case {case}");
            assert_eq!(metrics.argument_bytes, args.len(), "case {case}");
            assert_ne!(masked, args, "plaintext suffix survived fuzz case {case}");
            let error = report.reassemble_checked(&clean).unwrap_err();
            assert!(error.contains("observes CODESIZE"), "case {case}: {error}");
        }
    }

    #[tokio::test]
    async fn full_pipeline_rejects_constructor_mask_that_would_relocate_codesize() {
        let mut args = [0x33; 32].to_vec();
        args.extend_from_slice(&[0x44; 32]);
        let full_creation = supported_creation_with_args(&args);
        let full_hex = format!("0x{}", hex::encode(&full_creation));
        let seed = Seed::from_bytes([0x77; 32]);
        let mut config = ObfuscationConfig::with_seed(seed);
        config.obfuscate_constructor_arguments = true;

        let error = obfuscate_bytecode(&full_hex, SUPPORTED_RUNTIME, config)
            .await
            .expect_err("moving a CODESIZE-observing init program must fail closed");
        assert!(error.message.contains("observes CODESIZE"), "{error:?}");

        // The synthetic fixture itself is executable and deploys the supplied runtime;
        // rejection is caused by the relocation proof boundary, not malformed test bytecode.
        let original_runtime = deploy(&full_creation).0;
        assert_eq!(
            original_runtime.as_ref(),
            hex::decode(SUPPORTED_RUNTIME.trim_start_matches("0x")).unwrap()
        );
    }

    #[tokio::test]
    async fn full_pipeline_suppresses_constructor_mask_when_init_observes_gas() {
        let args = argument_words([0x22; 20], [0x33; 32], [0; 32]);
        let full_creation = escrow_creation_with_args(&args);
        let full_hex = format!("0x{}", hex::encode(&full_creation));
        let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x78; 32]));
        config.obfuscate_constructor_arguments = true;

        let protected = obfuscate_bytecode(&full_hex, ESCROW_RUNTIME, config)
            .await
            .expect("GAS-observing init must conservatively produce an identity artifact");

        assert_eq!(protected.obfuscated_bytecode, full_hex);
        assert!(!protected.metadata.constructor_args_obfuscated);
        assert_eq!(protected.metadata.constructor_argument_bytes, 0);
    }

    #[tokio::test]
    async fn oversized_constructor_mask_fails_closed() {
        let mut args = vec![0x5a; 32];
        args.resize(20_000, 0x5a);
        let full_hex = format!("0x{}", hex::encode(supported_creation_with_args(&args)));
        let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x88; 32]));
        config.obfuscate_constructor_arguments = true;

        let error = obfuscate_bytecode(&full_hex, SUPPORTED_RUNTIME, config)
            .await
            .unwrap_err();

        assert!(
            error.message.contains("exceeds an EVM size limit")
                || error.message.contains("exceeds PUSH2 capacity")
                || error.message.contains("observes CODESIZE"),
            "unexpected fail-closed error: {}",
            error.message
        );
    }

    #[test]
    #[ignore = "release-mode benchmark; run explicitly with --ignored --nocapture"]
    fn benchmark_constructor_argument_mask_generation() {
        let args = argument_words([0x22; 20], [0x33; 32], [0x44; 32]);
        let original = supported_creation_with_args(&args);
        let iterations = 100u64;
        let started = Instant::now();
        let mut decoder_bytes = 0usize;
        let mut min_decoder = usize::MAX;
        let mut max_decoder = 0usize;
        let mut representative_mask = None;

        for index in 0..iterations {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&index.to_be_bytes());
            let (clean, mut report, metrics) = mask_report(&original, &Seed::from_bytes(seed));
            decoder_bytes += metrics.decoder_bytes;
            min_decoder = min_decoder.min(metrics.decoder_bytes);
            max_decoder = max_decoder.max(metrics.decoder_bytes);
            representative_mask.get_or_insert_with(|| masked_arguments(&report));
            let error = report.reassemble_checked(&clean).unwrap_err();
            assert!(error.contains("observes CODESIZE"));
        }
        let elapsed = started.elapsed();
        let masked = representative_mask.unwrap();
        println!(
            "MASK_GENERATION argument_bytes={} representative_mask_bytes={} \
             avg_decoder_bytes={:.1} min_decoder_bytes={} \
             max_decoder_bytes={} avg_transform_us={:.1}",
            args.len(),
            masked.len(),
            decoder_bytes as f64 / iterations as f64,
            min_decoder,
            max_decoder,
            elapsed.as_micros() as f64 / iterations as f64,
        );
    }
}
