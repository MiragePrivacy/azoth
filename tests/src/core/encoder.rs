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
        op: Opcode::UNKNOWN(0xaa),
        imm: None,
    };
    let original = vec![0xaa; 43]; // Ensure PC 42 exists
    let bytes = encode(&[ins], &original).unwrap();
    assert_eq!(bytes, vec![0xaa]);
}

#[test]
fn encode_invalid_opcode_is_always_fe() {
    let ins = Instruction {
        pc: 0,
        op: Opcode::INVALID,
        imm: None,
    };
    // INVALID is the concrete 0xfe opcode; native decoding never uses it as an unknown marker.
    let original = vec![0x5c];
    let result = encode(&[ins], &original);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0xfe]);
}

#[test]
fn encode_invalid_opcode_never_silently_disappears() {
    let ins = Instruction {
        pc: 42,
        op: Opcode::INVALID,
        imm: None,
    };
    let original = vec![0x60, 0x01];
    let result = encode(&[ins], &original);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0xfe]);
}
