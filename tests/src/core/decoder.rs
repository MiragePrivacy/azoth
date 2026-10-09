use azoth_core::decoder::{
    decode_bytes, decode_executable_bytes, decode_input, format_assembly, SourceType,
};
use azoth_core::encoder::encode;
use azoth_core::Opcode;
use revm::bytecode::{Bytecode, BytecodeIterator, LegacyRawBytecode, OpCode as RevmOpcode};
use revm::primitives::Bytes;

const STORAGE: &str = include_str!("../../bytecode/storage.hex");
const COUNTER_DEPLOYMENT: &str = include_str!("../../bytecode/counter/counter_deployment.hex");
const COUNTER_RUNTIME: &str = include_str!("../../bytecode/counter/counter_runtime.hex");
const NATIVE_DEPLOYMENT: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/native_deployment.hex");
const NATIVE_RUNTIME: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/native_runtime.hex");
const ERC20_DEPLOYMENT: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/erc20_deployment.hex");
const ERC20_RUNTIME: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/erc20_runtime.hex");

fn bytes(hex_source: &str) -> Vec<u8> {
    hex::decode(hex_source.trim().trim_start_matches("0x")).expect("fixture is valid hex")
}

/// Returns the EVM instruction prefix and the Solidity CBOR compiler trailer.
fn split_compiler_trailer(input: &[u8]) -> (&[u8], &[u8]) {
    assert!(input.len() >= 2, "fixture must contain a compiler trailer");
    let payload_len = usize::from(u16::from_be_bytes([
        input[input.len() - 2],
        input[input.len() - 1],
    ]));
    let trailer_len = payload_len
        .checked_add(2)
        .expect("two-byte compiler length cannot overflow");
    let split = input
        .len()
        .checked_sub(trailer_len)
        .expect("compiler trailer length is in bounds");
    input.split_at(split)
}

#[test]
fn exhaustive_opcode_stream_matches_revm_instruction_boundaries() {
    // Put every possible opcode byte in code position. PUSH immediates are deliberately filled
    // with opcode-looking bytes; an implementation that accidentally decodes an immediate will
    // disagree with revm's independently maintained legacy-bytecode iterator.
    let mut corpus = Vec::new();
    for opcode in 0u8..=u8::MAX {
        corpus.push(opcode);
        if (0x60..=0x7f).contains(&opcode) {
            let width = usize::from(opcode - 0x5f);
            corpus.extend((0..width).map(|index| {
                const OPCODE_LIKE: [u8; 8] = [0x5b, 0x60, 0x7f, 0x56, 0xfe, 0xaa, 0x00, 0xff];
                OPCODE_LIKE[index % OPCODE_LIKE.len()]
            }));
        }
    }

    let instructions =
        decode_executable_bytes(&corpus).expect("complete exhaustive stream must decode");

    let analyzed = LegacyRawBytecode(Bytes::copy_from_slice(&corpus)).into_analyzed();
    let bytecode = Bytecode::LegacyAnalyzed(analyzed);
    let mut oracle = BytecodeIterator::new(&bytecode);
    let mut expected = Vec::new();
    while oracle.position() < corpus.len() {
        let pc = oracle.position();
        let opcode = oracle.next().expect("original bytes remain");
        expected.push((pc, opcode));
    }

    let actual: Vec<_> = instructions
        .iter()
        .map(|instruction| (instruction.pc, instruction.op.to_byte()))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        encode(&instructions, &corpus).expect("exhaustive stream must re-encode"),
        corpus
    );
}

#[test]
fn opcode_metadata_matches_revm_for_every_byte() {
    for byte in u8::MIN..=u8::MAX {
        let native = Opcode::from_byte(byte);
        match RevmOpcode::new(byte) {
            Some(reference) => {
                assert!(!native.is_unknown(), "known-byte mismatch at 0x{byte:02x}");
                assert_eq!(
                    native.to_string(),
                    reference.as_str(),
                    "mnemonic mismatch at 0x{byte:02x}"
                );
                let info = native.info().expect("known native opcode has metadata");
                assert_eq!(
                    (info.inputs, info.outputs),
                    reference.input_output(),
                    "stack-effect mismatch at 0x{byte:02x}"
                );
                assert_eq!(
                    native.immediate_size(),
                    usize::from(reference.info().immediate_size()),
                    "immediate-width mismatch at 0x{byte:02x}"
                );
                assert_eq!(
                    native.is_terminal(),
                    reference.info().is_terminating(),
                    "terminal classification mismatch at 0x{byte:02x}"
                );
            }
            None => {
                assert_eq!(native, Opcode::UNKNOWN(byte), "byte 0x{byte:02x}");
                assert_eq!(native.info(), None);
                assert_eq!(native.immediate_size(), 0);
                assert!(native.is_terminal());
            }
        }
    }
}

#[test]
fn every_push_width_captures_exact_immediate_and_size() {
    for width in 1u8..=32 {
        let opcode = 0x5f + width;
        let immediate: Vec<_> = (0..width).map(|index| index.wrapping_mul(17)).collect();
        let mut input = Vec::with_capacity(usize::from(width) + 2);
        input.push(opcode);
        input.extend_from_slice(&immediate);
        input.push(0x00);

        let instructions =
            decode_executable_bytes(&input).expect("complete PUSH must decode strictly");
        assert_eq!(instructions.len(), 2, "PUSH{width}");
        assert_eq!(instructions[0].pc, 0, "PUSH{width}");
        assert_eq!(instructions[0].op, Opcode::PUSH(width), "PUSH{width}");
        let encoded_immediate = hex::encode(&immediate);
        assert_eq!(
            instructions[0].imm.as_deref(),
            Some(encoded_immediate.as_str()),
            "PUSH{width}"
        );
        assert_eq!(instructions[0].byte_size(), usize::from(width) + 1);
        assert_eq!(instructions[1].pc, usize::from(width) + 1);
        assert_eq!(instructions[1].op, Opcode::STOP);
        assert_eq!(
            encode(&instructions, &input).expect("PUSH stream must re-encode"),
            input
        );
    }
}

#[test]
fn every_truncated_push_fails_strictly_but_round_trips_losslessly() {
    for width in 1u8..=32 {
        for available in 0..usize::from(width) {
            // A leading STOP is important: Heimdall used to return partial success when a
            // truncated PUSH followed one or more valid instructions.
            let mut input = vec![0x00, 0x5f + width];
            input.extend((0..available).map(|index| index as u8));

            let error = decode_executable_bytes(&input)
                .expect_err("truncated executable PUSH must never yield partial success");
            let message = error.to_string();
            assert!(
                message.contains(&format!("PUSH{width}")),
                "error omits declared width for PUSH{width} with {available} bytes: {message}"
            );
            assert!(
                message.contains("0x1") || message.contains("pc 1") || message.contains("PC 1"),
                "error omits nonzero failing PC for PUSH{width} with {available} bytes: {message}"
            );

            let instructions = decode_bytes(&input).expect("blob decoding must remain lossless");
            assert_eq!(instructions.len(), 2, "PUSH{width}, available={available}");
            let truncated = &instructions[1];
            assert_eq!(truncated.pc, 1);
            assert_eq!(truncated.op, Opcode::PUSH(width));
            assert_eq!(
                truncated.imm.as_deref(),
                Some(hex::encode(&input[2..]).as_str())
            );
            assert_eq!(truncated.byte_size(), available + 1);
            assert_eq!(
                encode(&instructions, &input).expect("final short PUSH must re-encode exactly"),
                input
            );
        }
    }
}

#[test]
fn opcode_looking_push_data_is_not_decoded_as_code() {
    let input = [0x65, 0x5b, 0x60, 0x7f, 0xfe, 0xaa, 0x00, 0x00];
    let instructions = decode_executable_bytes(&input).expect("complete PUSH6 must decode");

    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[0].op, Opcode::PUSH(6));
    assert_eq!(instructions[0].imm.as_deref(), Some("5b607ffeaa00"));
    assert_eq!(instructions[1].pc, 7);
    assert_eq!(instructions[1].op, Opcode::STOP);
}

#[test]
fn unknown_bytes_remain_distinct_from_designated_invalid() {
    let input = [0x0c, 0xaa, 0xd0, 0xe0, 0xf7, 0xfe];
    let instructions =
        decode_executable_bytes(&input).expect("one-byte legacy opcodes must decode");
    let opcodes: Vec<_> = instructions
        .iter()
        .map(|instruction| instruction.op)
        .collect();

    assert_eq!(
        opcodes,
        vec![
            Opcode::UNKNOWN(0x0c),
            Opcode::UNKNOWN(0xaa),
            Opcode::UNKNOWN(0xd0),
            Opcode::UNKNOWN(0xe0),
            Opcode::UNKNOWN(0xf7),
            Opcode::INVALID,
        ]
    );
    assert_eq!(
        encode(&instructions, &input).expect("unknown bytes must round-trip losslessly"),
        input
    );
}

#[test]
fn checked_in_contract_artifacts_round_trip_losslessly() {
    let fixtures = [
        ("storage", STORAGE),
        ("counter deployment", COUNTER_DEPLOYMENT),
        ("counter runtime", COUNTER_RUNTIME),
        ("native escrow deployment", NATIVE_DEPLOYMENT),
        ("native escrow runtime", NATIVE_RUNTIME),
        ("ERC20 escrow deployment", ERC20_DEPLOYMENT),
        ("ERC20 escrow runtime", ERC20_RUNTIME),
    ];

    for (name, source) in fixtures {
        let artifact = bytes(source);
        let instructions = decode_bytes(&artifact)
            .unwrap_or_else(|error| panic!("{name} did not decode: {error}"));
        let encoded = encode(&instructions, &artifact)
            .unwrap_or_else(|error| panic!("{name} did not encode: {error}"));
        assert_eq!(encoded, artifact, "{name} full artifact changed");

        // The executable prefix must also satisfy the strict decoder. Compiler data stays opaque.
        let (code, _trailer) = split_compiler_trailer(&artifact);
        let strict = decode_executable_bytes(code)
            .unwrap_or_else(|error| panic!("{name} code prefix did not decode: {error}"));
        assert_eq!(
            encode(&strict, code).expect("strict instruction prefix must encode"),
            code,
            "{name} code prefix changed"
        );

        let mut expected_pc = 0usize;
        for instruction in &instructions {
            assert_eq!(instruction.pc, expected_pc, "gap in {name}");
            expected_pc += instruction.byte_size();
        }
        assert_eq!(expected_pc, artifact.len(), "incomplete coverage in {name}");
    }
}

#[test]
fn input_wrapper_computes_metadata_without_changing_native_decode() {
    let decoded = decode_input(STORAGE, false).expect("storage fixture must decode");
    assert_eq!(decoded.info.source, SourceType::HexString);
    assert_eq!(decoded.info.byte_length, decoded.bytes.len());
    assert_eq!(
        decoded.instructions,
        decode_bytes(&decoded.bytes).expect("same bytes must decode identically")
    );
    assert!(decoded.info.keccak_hash.iter().any(|byte| *byte != 0));
}

#[test]
fn assembly_rendering_is_explicit_and_deterministic() {
    let input = [0x60, 0x01, 0x5f, 0xaa, 0xfe, 0x00];
    let instructions = decode_executable_bytes(&input).expect("sample must decode");
    let first = format_assembly(&instructions);
    let second = format_assembly(&instructions);

    assert_eq!(first, second);
    assert_eq!(first.lines().count(), instructions.len());
    assert!(first.contains("PUSH1"));
    assert!(first.contains("PUSH0"));
    assert!(first.contains("UNKNOWN"));
    assert!(first.contains("INVALID"));
    for instruction in &instructions {
        assert!(
            first.lines().any(|line| line == instruction.to_string()),
            "render omitted {instruction}"
        );
    }
}

#[test]
fn malformed_hex_still_fails_before_instruction_decoding() {
    assert!(decode_input("0xZZ42", false).is_err());
}

#[test]
fn opcode_serialization_is_stable_and_self_describing() {
    assert_eq!(serde_json::to_string(&Opcode::ADD).unwrap(), r#""ADD""#);
    assert_eq!(
        serde_json::to_string(&Opcode::PUSH(4)).unwrap(),
        r#"{"PUSH":4}"#
    );
    assert_eq!(
        serde_json::to_string(&Opcode::UNKNOWN(0xd0)).unwrap(),
        r#"{"UNKNOWN":208}"#
    );

    assert!(serde_json::from_str::<Opcode>(r#"{"PUSH":0}"#).is_err());
    assert!(serde_json::from_str::<Opcode>(r#"{"DUP":17}"#).is_err());
    assert!(serde_json::from_str::<Opcode>(r#"{"SWAP":0}"#).is_err());
    assert!(serde_json::from_str::<Opcode>(r#"{"UNKNOWN":86}"#).is_err());
    assert_eq!(
        serde_json::from_str::<Opcode>(r#"{"UNKNOWN":208}"#).unwrap(),
        Opcode::UNKNOWN(0xd0)
    );
}

#[test]
fn deterministic_arbitrary_byte_corpus_round_trips_exactly() {
    // A local xorshift generator keeps this regression corpus dependency-free and reproducible.
    // The test exercises empty inputs, every short length, and larger irregular blobs.
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    for case in 0..10_000usize {
        let len = if case < 256 {
            case
        } else {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state as usize) % 2_048
        };

        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            input.push(state as u8);
        }

        let instructions = decode_bytes(&input).expect("native raw decode is total");
        assert_eq!(
            encode(&instructions, &input).expect("decoded bytes must re-encode"),
            input,
            "lossless round-trip failed for corpus case {case}"
        );

        let has_short_final_push = instructions
            .last()
            .is_some_and(|instruction| instruction.is_truncated_push());
        assert_eq!(
            decode_executable_bytes(&input).is_err(),
            has_short_final_push,
            "strict-mode result disagrees with decoded boundary for corpus case {case}"
        );

        let mut expected_pc = 0usize;
        for instruction in &instructions {
            assert_eq!(instruction.pc, expected_pc, "PC gap in corpus case {case}");
            expected_pc += instruction.byte_size();
        }
        assert_eq!(expected_pc, input.len(), "coverage mismatch in case {case}");
    }
}
