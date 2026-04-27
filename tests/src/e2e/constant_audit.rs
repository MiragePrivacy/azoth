use super::{
    deploy_contract_and_get_runtime, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
    ESCROW_CONTRACT_RUNTIME_BYTECODE,
};
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use std::collections::{BTreeMap, BTreeSet};

const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const REPORT_PATTERNS: &[(&str, &str)] = &[
    ("USDC address", "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
    (
        "ERC-20 Transfer topic",
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    ),
    ("ERC-20 transfer selector", "a9059cbb"),
    ("ERC-20 transferFrom selector", "23b872dd"),
    ("linked Mirage address prefix", "bb83df95"),
    ("deployer address prefix", "40e0b656"),
    ("bond timeout 300", "012c"),
    ("USDC decimals 1e6", "0f4240"),
    ("Solidity Panic selector", "4e487b71"),
    ("Solidity Error(string) selector", "08c379a0"),
    (
        "proof token fixture",
        "be41a9ec942d5b52be07cc7f4d7e30e10e9b652a",
    ),
    (
        "proof recipient fixture",
        "658d9c76ff358984d6436ea11ee1eda08894c818",
    ),
    (
        "proof executor fixture",
        "e1a9d9c9abb872ddef70a4d108fd8fc3c7ce4dc4",
    ),
];

#[tokio::test]
async fn default_pipeline_removes_report_constants_from_real_escrow_bytecode() -> Result<()> {
    let seed = Seed::from_hex(FIXED_SEED).map_err(|e| eyre!("seed parse failed: {e}"))?;
    let config = ObfuscationConfig {
        seed,
        ..ObfuscationConfig::default()
    };
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("default pipeline obfuscation failed: {e}"))?;

    let deployment = normalize_hex(&result.obfuscated_bytecode);
    let runtime = hex::encode(deploy_contract_and_get_runtime(
        &result.obfuscated_bytecode,
    )?);
    let audited_patterns = audited_patterns()?;

    assert!(
        audited_patterns.iter().any(|(_, hex)| hex == "045c4b02"),
        "audit should include optimized custom-error selector 0x045c4b02"
    );

    assert_no_raw_matches("obfuscated deployment", &deployment, &audited_patterns);
    assert_no_raw_matches("deployed runtime", &runtime, &audited_patterns);
    assert_no_shifted_selector_recovery("obfuscated deployment", &deployment, &audited_patterns)?;
    assert_no_shifted_selector_recovery("deployed runtime", &runtime, &audited_patterns)?;
    assert_no_raw_selector_byte_patches("obfuscated deployment", &deployment, &audited_patterns)?;
    assert_no_raw_selector_byte_patches("deployed runtime", &runtime, &audited_patterns)?;
    assert_no_constant_folder_recovery("obfuscated deployment", &deployment, &audited_patterns)?;
    assert_no_constant_folder_recovery("deployed runtime", &runtime, &audited_patterns)?;

    Ok(())
}

fn audited_patterns() -> Result<BTreeSet<(String, String)>> {
    let mut patterns = BTreeSet::new();
    for (name, hex) in REPORT_PATTERNS {
        patterns.insert(((*name).to_string(), normalize_hex(hex)));
    }

    for selector in collect_revert_selectors(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE)? {
        patterns.insert((
            format!("original custom-error selector {selector}"),
            selector,
        ));
    }
    for selector in collect_revert_selectors(ESCROW_CONTRACT_RUNTIME_BYTECODE)? {
        patterns.insert((
            format!("original custom-error selector {selector}"),
            selector,
        ));
    }

    Ok(patterns)
}

fn assert_no_raw_matches(label: &str, haystack: &str, patterns: &BTreeSet<(String, String)>) {
    for (name, needle) in patterns {
        assert!(
            !haystack.contains(needle),
            "{label} still contains {name}: 0x{needle}"
        );
    }
}

fn assert_no_shifted_selector_recovery(
    label: &str,
    bytecode_hex: &str,
    patterns: &BTreeSet<(String, String)>,
) -> Result<()> {
    let audited_selectors: BTreeSet<&str> = patterns
        .iter()
        .map(|(_, hex)| hex.as_str())
        .filter(|hex| hex.len() == 8)
        .collect();
    let recovered = collect_shifted_selectors(bytecode_hex)?;

    for selector in recovered {
        assert!(
            !audited_selectors.contains(selector.as_str()),
            "{label} reconstructs audited selector via PUSH/SHL: 0x{selector}"
        );
    }

    Ok(())
}

fn assert_no_raw_selector_byte_patches(
    label: &str,
    bytecode_hex: &str,
    patterns: &BTreeSet<(String, String)>,
) -> Result<()> {
    let bytes = decode_hex(bytecode_hex)?;
    for (name, selector) in patterns.iter().filter(|(_, hex)| hex.len() == 8) {
        let selector_bytes = decode_hex(selector)?;
        for (offset, byte) in selector_bytes.iter().enumerate() {
            assert!(
                !contains_direct_mstore8_patch(&bytes, offset, *byte),
                "{label} directly patches {name} byte[{offset}] via raw PUSH1 0x{byte:02x}; MSTORE8"
            );
        }
    }

    Ok(())
}

fn contains_direct_mstore8_patch(bytes: &[u8], offset: usize, value: u8) -> bool {
    for idx in 0..bytes.len() {
        if offset == 0 {
            if bytes.get(idx..idx + 4) == Some(&[0x60, value, 0x81, 0x53]) {
                return true;
            }
        } else if bytes.get(idx..idx + 7)
            == Some(&[0x60, value, 0x60, offset as u8, 0x82, 0x01, 0x53])
        {
            return true;
        }
    }

    false
}

fn assert_no_constant_folder_recovery(
    label: &str,
    bytecode_hex: &str,
    patterns: &BTreeSet<(String, String)>,
) -> Result<()> {
    let bytes = decode_hex(bytecode_hex)?;
    let audit_values = constant_folder_audit_values(patterns)?;
    for (pc, value) in collect_folded_values(&bytes) {
        if let Some(name) = audit_values.get(&value) {
            return Err(eyre!(
                "{label} constant-folder recovered {name} at pc=0x{pc:x}"
            ));
        }
    }

    Ok(())
}

fn constant_folder_audit_values(
    patterns: &BTreeSet<(String, String)>,
) -> Result<BTreeMap<[u8; 32], String>> {
    let mut values = BTreeMap::new();
    for (name, hex) in patterns {
        let bytes = decode_hex(hex)?;
        if bytes.len() > 32 {
            continue;
        }

        values.insert(right_aligned_word(&bytes), name.clone());
        if bytes.len() == 4 {
            values.insert(left_aligned_word(&bytes), format!("{name} left-aligned"));
        }
    }
    Ok(values)
}

fn collect_folded_values(bytes: &[u8]) -> Vec<(usize, [u8; 32])> {
    let mut values = Vec::new();
    let mut stack: Vec<Option<[u8; 32]>> = Vec::new();
    let mut idx = 0usize;

    while idx < bytes.len() {
        let pc = idx;
        let opcode = bytes[idx];
        idx += 1;

        let folded = match opcode {
            0x5f => {
                let value = [0u8; 32];
                stack.push(Some(value));
                Some(value)
            }
            0x60..=0x7f => {
                let width = (opcode - 0x5f) as usize;
                if idx + width > bytes.len() {
                    break;
                }
                let value = right_aligned_word(&bytes[idx..idx + width]);
                idx += width;
                stack.push(Some(value));
                Some(value)
            }
            0x01 => fold_binary(&mut stack, add_words),
            0x03 => fold_binary(&mut stack, |left, right| sub_words(right, left)),
            0x10 => fold_binary(&mut stack, |left, right| gt_word(right, left)),
            0x11 => fold_binary(&mut stack, |left, right| lt_word(right, left)),
            0x14 => fold_binary(&mut stack, eq_word),
            0x15 => fold_unary(&mut stack, iszero_word),
            0x16 => fold_binary(&mut stack, and_words),
            0x17 => fold_binary(&mut stack, or_words),
            0x18 => fold_binary(&mut stack, xor_words),
            0x19 => fold_unary(&mut stack, not_word),
            0x1a => fold_binary(&mut stack, byte_word),
            0x1b => fold_binary(&mut stack, shl_word),
            0x1c => fold_binary(&mut stack, shr_word),
            0x30 | 0x33 | 0x34 | 0x36 | 0x38 | 0x3a | 0x3d | 0x42 | 0x43 | 0x58 | 0x59 | 0x5a => {
                stack.push(None);
                None
            }
            0x50 => {
                stack.pop();
                None
            }
            0x5b => {
                stack.clear();
                None
            }
            0x80..=0x8f => {
                let depth = (opcode - 0x7f) as usize;
                if depth <= stack.len() {
                    let value = stack[stack.len() - depth];
                    stack.push(value);
                    value
                } else {
                    stack.clear();
                    None
                }
            }
            0x90..=0x9f => {
                let depth = (opcode - 0x8f) as usize;
                if depth < stack.len() {
                    let top = stack.len() - 1;
                    stack.swap(top, top - depth);
                } else {
                    stack.clear();
                }
                None
            }
            _ => {
                stack.clear();
                None
            }
        };

        if let Some(value) = folded {
            values.push((pc, value));
        }
    }

    values
}

fn fold_unary(stack: &mut Vec<Option<[u8; 32]>>, op: fn([u8; 32]) -> [u8; 32]) -> Option<[u8; 32]> {
    let Some(value) = stack.pop() else {
        return None;
    };
    let result = value.map(op);
    stack.push(result);
    result
}

fn fold_binary(
    stack: &mut Vec<Option<[u8; 32]>>,
    op: fn([u8; 32], [u8; 32]) -> [u8; 32],
) -> Option<[u8; 32]> {
    let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
        return None;
    };
    let result = match (left, right) {
        (Some(left), Some(right)) => Some(op(left, right)),
        _ => None,
    };
    stack.push(result);
    result
}

fn collect_revert_selectors(bytecode_hex: &str) -> Result<BTreeSet<String>> {
    let bytes = decode_hex(bytecode_hex)?;
    let mut selectors = BTreeSet::new();

    for idx in 0..bytes.len() {
        if let Some((selector, end)) = shifted_selector_at(&bytes, idx) {
            if !is_builtin_error_selector(selector) && has_nearby_mstore_then_revert(&bytes, end) {
                selectors.insert(format!("{selector:08x}"));
            }
        }

        if let Some((selector, end)) = left_aligned_push32_selector_at(&bytes, idx) {
            if !is_builtin_error_selector(selector) && has_nearby_mstore_then_revert(&bytes, end) {
                selectors.insert(format!("{selector:08x}"));
            }
        }
    }

    Ok(selectors)
}

fn collect_shifted_selectors(bytecode_hex: &str) -> Result<BTreeSet<String>> {
    let bytes = decode_hex(bytecode_hex)?;
    let mut selectors = BTreeSet::new();

    for idx in 0..bytes.len() {
        if let Some((selector, _)) = shifted_selector_at(&bytes, idx) {
            selectors.insert(format!("{selector:08x}"));
        }
    }

    Ok(selectors)
}

fn shifted_selector_at(bytes: &[u8], idx: usize) -> Option<(u32, usize)> {
    let opcode = *bytes.get(idx)?;
    if !(0x60..=0x63).contains(&opcode) {
        return None;
    }

    let width = (opcode - 0x5f) as usize;
    let shift_pos = idx + 1 + width;
    if *bytes.get(shift_pos)? != 0x60 || *bytes.get(shift_pos + 2)? != 0x1b {
        return None;
    }

    let value = parse_usize_be(&bytes[idx + 1..idx + 1 + width])?;
    let shift = *bytes.get(shift_pos + 1)? as usize;
    let selector = recover_left_aligned_selector(value, shift)?;
    Some((selector, shift_pos + 3))
}

fn left_aligned_push32_selector_at(bytes: &[u8], idx: usize) -> Option<(u32, usize)> {
    if *bytes.get(idx)? != 0x7f || idx + 33 > bytes.len() {
        return None;
    }

    let immediate = &bytes[idx + 1..idx + 33];
    if immediate[4..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let selector = u32::from_be_bytes([immediate[0], immediate[1], immediate[2], immediate[3]]);
    if selector == 0 {
        return None;
    }

    Some((selector, idx + 33))
}

fn recover_left_aligned_selector(value: usize, shift: usize) -> Option<u32> {
    if shift < 224 {
        return None;
    }
    let extra_shift = shift - 224;
    if extra_shift >= 32 {
        return None;
    }
    let selector = (value as u64).checked_shl(extra_shift as u32)?;
    if selector == 0 || selector > u32::MAX as u64 {
        return None;
    }
    Some(selector as u32)
}

fn has_nearby_mstore_then_revert(bytes: &[u8], start: usize) -> bool {
    let end = (start + 64).min(bytes.len());
    let mut saw_mstore = false;
    let mut idx = start;

    while idx < end {
        let opcode = bytes[idx];
        match opcode {
            0x52 => saw_mstore = true,
            0xfd => return saw_mstore,
            0x00 | 0x56 | 0x57 | 0xf1 | 0xf3 | 0xf4 | 0xfa => return false,
            0x60..=0x7f => {
                idx += 1 + (opcode - 0x5f) as usize;
                continue;
            }
            _ => {}
        }
        idx += 1;
    }

    false
}

fn is_builtin_error_selector(selector: u32) -> bool {
    matches!(selector, 0x08c3_79a0 | 0x4e48_7b71)
}

fn right_aligned_word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    word
}

fn left_aligned_word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[..bytes.len()].copy_from_slice(bytes);
    word
}

fn add_words(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for idx in (0..32).rev() {
        let sum = left[idx] as u16 + right[idx] as u16 + carry;
        out[idx] = sum as u8;
        carry = sum >> 8;
    }
    out
}

fn sub_words(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for idx in (0..32).rev() {
        let diff = left[idx] as i16 - right[idx] as i16 - borrow;
        if diff < 0 {
            out[idx] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[idx] = diff as u8;
            borrow = 0;
        }
    }
    out
}

fn and_words(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for idx in 0..32 {
        out[idx] = left[idx] & right[idx];
    }
    out
}

fn or_words(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for idx in 0..32 {
        out[idx] = left[idx] | right[idx];
    }
    out
}

fn xor_words(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for idx in 0..32 {
        out[idx] = left[idx] ^ right[idx];
    }
    out
}

fn not_word(value: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for idx in 0..32 {
        out[idx] = !value[idx];
    }
    out
}

fn eq_word(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    bool_word(left == right)
}

fn lt_word(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    bool_word(left < right)
}

fn gt_word(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    bool_word(left > right)
}

fn iszero_word(value: [u8; 32]) -> [u8; 32] {
    bool_word(value.iter().all(|byte| *byte == 0))
}

fn bool_word(value: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = u8::from(value);
    out
}

fn byte_word(value: [u8; 32], index: [u8; 32]) -> [u8; 32] {
    let Some(index) = word_to_usize(index) else {
        return [0u8; 32];
    };
    let mut out = [0u8; 32];
    if index < 32 {
        out[31] = value[index];
    }
    out
}

fn shl_word(value: [u8; 32], shift: [u8; 32]) -> [u8; 32] {
    let Some(shift) = word_to_usize(shift) else {
        return [0u8; 32];
    };
    if shift >= 256 {
        return [0u8; 32];
    }

    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    let mut out = [0u8; 32];
    for (idx, out_byte) in out.iter_mut().enumerate() {
        let src = idx + byte_shift;
        if src >= 32 {
            continue;
        }
        *out_byte |= value[src] << bit_shift;
        if bit_shift > 0 && src + 1 < 32 {
            *out_byte |= value[src + 1] >> (8 - bit_shift);
        }
    }
    out
}

fn shr_word(value: [u8; 32], shift: [u8; 32]) -> [u8; 32] {
    let Some(shift) = word_to_usize(shift) else {
        return [0u8; 32];
    };
    if shift >= 256 {
        return [0u8; 32];
    }

    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    let mut out = [0u8; 32];
    for (idx, out_byte) in out.iter_mut().enumerate() {
        if idx < byte_shift {
            continue;
        }
        let src = idx - byte_shift;
        *out_byte |= value[src] >> bit_shift;
        if bit_shift > 0 && src > 0 {
            *out_byte |= value[src - 1] << (8 - bit_shift);
        }
    }
    out
}

fn word_to_usize(value: [u8; 32]) -> Option<usize> {
    if value[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    parse_usize_be(&value[24..])
}

fn parse_usize_be(bytes: &[u8]) -> Option<usize> {
    if bytes.len() > std::mem::size_of::<usize>()
        && bytes[..bytes.len() - std::mem::size_of::<usize>()]
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }

    let mut value = 0usize;
    for byte in bytes {
        value = value.checked_shl(8)? | *byte as usize;
    }
    Some(value)
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    hex::decode(normalize_hex(hex)).map_err(|e| eyre!("hex decode failed: {e}"))
}

fn normalize_hex(hex: &str) -> String {
    hex.trim()
        .trim_start_matches("0x")
        .replace('_', "")
        .to_ascii_lowercase()
}
