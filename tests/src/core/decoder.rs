use azoth_core::decoder::{decode_bytecode, parse_assembly, SourceType};
use azoth_core::result::Error;
use heimdall::{disassemble, DisassemblerArgsBuilder};

#[allow(dead_code)]
// Fixture: PUSH1 0x01, PUSH1 0x02, ADD, STOP
const BYTECODE: &str = "0x6001600201600057";

#[tokio::test]
async fn test_hex_roundtrip() {
    let (ins, info, asm, _) = decode_bytecode(BYTECODE, false).await.unwrap();
    tracing::debug!("\nRaw assembly:\n{}", asm);
    tracing::debug!("Parsed instructions:");
    for instruction in &ins {
        tracing::debug!("{}", instruction);
    }
    assert_eq!(ins.len(), 5);

    let expected_bytes = BYTECODE.trim_start_matches("0x").len() / 2;
    assert_eq!(info.byte_length, expected_bytes);

    assert_eq!(info.source, SourceType::HexString);
    assert!(!info.keccak_hash.is_empty());
}

#[tokio::test]
async fn test_bad_hex_fails() {
    let result = decode_bytecode("0xZZ42", false).await;
    assert!(matches!(result, Err(Error::HexDecode(_))));
}

#[tokio::test]
async fn test_invalid_assembly_fails() {
    let args = DisassemblerArgsBuilder::new()
        .target("0x".to_string()) // Empty bytecode
        .output("print".into())
        .build()
        .unwrap();
    let asm = disassemble(args)
        .await
        .map_err(|e| Error::Heimdall(e.to_string()));
    match asm {
        Ok(asm) => {
            tracing::debug!("\nRaw assembly from invalid input:\n{}", asm);
            let result = parse_assembly(&asm);
            assert!(matches!(result, Err(Error::ParseError { .. })));
        }
        Err(e) => assert!(matches!(e, Error::Heimdall(_))),
    }
}
