use azoth_core::decoder::Instruction;
use azoth_core::encoder::encode;
use azoth_core::Opcode;

#[test]
fn encode_push1() {
    let ins = Instruction {
        pc: 0,
        op: Opcode::PUSH(1),
        imm: Some("aa".to_string()),
    };
    let original = vec![0x60, 0xaa];
    let bytes = encode(&[ins], &original).unwrap();
    assert_eq!(bytes, vec![0x60, 0xaa]);
}

#[test]
fn encode_jumpdest() {
    let ins = Instruction {
        pc: 0,
        op: Opcode::JUMPDEST,
        imm: None,
    };
    let original = vec![0x5b];
    let bytes = encode(&[ins], &original).unwrap();
    assert_eq!(bytes, vec![0x5b]);
}

#[test]
fn encode_return() {
    let ins = Instruction {
        pc: 0,
        op: Opcode::RETURN,
        imm: None,
    };
    let original = vec![0xf3];
    let bytes = encode(&[ins], &original).unwrap();
    assert_eq!(bytes, vec![0xf3]);
}

#[test]
fn encode_unknown_hex_format() {
    let ins = Instruction {
        pc: 42,
        op: Opcode::UNKNOWN(0xfe),
        imm: None,
    };
    let original = vec![0xfe; 43]; // Ensure PC 42 exists
    let bytes = encode(&[ins], &original).unwrap();
    assert_eq!(bytes, vec![0xfe]);
}

#[test]
fn encode_invalid_opcode_with_original() {
    let ins = Instruction {
        pc: 0,
        op: Opcode::INVALID,
        imm: None,
    };
    // With original bytecode, INVALID opcode is preserved from original
    let original = vec![0x5c]; // Some unknown byte
    let result = encode(&[ins], &original);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0x5c]); // Preserved from original!
}

#[test]
fn encode_invalid_opcode_without_original_data() {
    let ins = Instruction {
        pc: 42,
        op: Opcode::INVALID,
        imm: None,
    };
    // PC 42 is beyond original bytecode, so it gets skipped
    let original = vec![0x60, 0x01]; // Only 2 bytes, PC 42 doesn't exist
    let result = encode(&[ins], &original);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Vec::<u8>::new()); // Empty - skipped!
}
