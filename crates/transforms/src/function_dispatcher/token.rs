//! Token generation for function dispatcher obfuscation.
//!
//! This module provides cryptographically-derived token generation for mapping
//! original function selectors to obfuscated tokens. The tokens maintain the same
//! byte width as original selectors to preserve dispatcher structure.

use crate::{Error, Result};
use azoth_core::detection::FunctionSelector;
use azoth_core::seed::Seed;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};

/// Generates a mapping from original 4-byte function selectors to derived 4-byte tokens.
///
/// Tokens always preserve the bytes at indices specified in `preserve_bytes`
/// (selector → byte_index). This is required for byte extraction patterns to
/// work correctly and must be enforced for every dispatcher layout.
pub fn generate_selector_token_mapping(
    selectors: &[FunctionSelector],
    seed: &Seed,
    preserve_bytes: &HashMap<u32, u8>, // selector -> byte_index to preserve
) -> Result<HashMap<u32, Vec<u8>>> {
    if selectors.is_empty() {
        return Ok(HashMap::new());
    }

    let mut hasher = Keccak256::new();
    hasher.update(b"AZOTH_DISPATCHER_TOKEN_SECRET");
    hasher.update(seed.as_bytes());
    let secret: [u8; 32] = hasher.finalize().into();

    let mut mapping = HashMap::with_capacity(selectors.len());
    let mut used_tokens = HashSet::with_capacity(selectors.len());

    // First validate all byte indices
    for (selector_val, &byte_index) in preserve_bytes.iter() {
        if byte_index >= 4 {
            return Err(Error::Generic(format!(
                "dispatcher: invalid byte_index {} for selector 0x{:08x} (must be 0-3)",
                byte_index, selector_val
            )));
        }
    }

    // Group selectors by their preserve_byte constraint to detect potential conflicts
    if !preserve_bytes.is_empty() {
        let mut byte_groups: HashMap<(u8, u8), Vec<u32>> = HashMap::new();
        for selector in selectors {
            if let Some(&byte_index) = preserve_bytes.get(&selector.selector) {
                let selector_bytes = selector.selector.to_be_bytes();
                let byte_value = selector_bytes[byte_index as usize];
                byte_groups
                    .entry((byte_index, byte_value))
                    .or_default()
                    .push(selector.selector);
            }
        }

        // Log constraint information for debugging
        for ((byte_index, byte_value), sels) in &byte_groups {
            tracing::debug!(
                "Token generation: {} selector(s) must preserve byte[{}]=0x{:02x}",
                sels.len(),
                byte_index,
                byte_value
            );
        }
    }

    for selector in selectors {
        let preserve_byte_index = preserve_bytes.get(&selector.selector).copied();

        // Validate byte index is in valid range
        if let Some(idx) = preserve_byte_index {
            if idx >= 4 {
                return Err(Error::Generic(format!(
                    "dispatcher: invalid byte_index {} for selector 0x{:08x} (must be 0-3)",
                    idx, selector.selector
                )));
            }
        }

        let token = derive_unique_selector_token(
            selector.selector,
            &secret,
            &mut used_tokens,
            preserve_byte_index,
        )?;

        // Verify the token preserves the required byte
        if let Some(byte_index) = preserve_byte_index {
            let selector_bytes = selector.selector.to_be_bytes();
            let token_bytes = token.to_be_bytes();
            if selector_bytes[byte_index as usize] != token_bytes[byte_index as usize] {
                return Err(Error::Generic(format!(
                    "dispatcher: token generation failed to preserve byte[{}] for selector 0x{:08x}",
                    byte_index, selector.selector
                )));
            }
        }

        mapping.insert(selector.selector, token.to_be_bytes().to_vec());
    }

    Ok(mapping)
}

/// Derives a unique 4-byte token for a given selector.
fn derive_unique_selector_token(
    selector: u32,
    secret: &[u8; 32],
    used_tokens: &mut HashSet<u32>,
    preserve_byte_index: Option<u8>,
) -> Result<u32> {
    const MAX_ATTEMPTS: u32 = 100_000;

    let selector_bytes = selector.to_be_bytes();
    let mut collision_count = 0;
    let mut selector_collision_count = 0;

    for counter in 0..MAX_ATTEMPTS {
        let mut hasher = Keccak256::new();
        hasher.update(secret);
        hasher.update(selector_bytes);
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();

        // Take the last 4 bytes of the hash as the candidate token
        let mut candidate_bytes = [
            hash[hash.len() - 4],
            hash[hash.len() - 3],
            hash[hash.len() - 2],
            hash[hash.len() - 1],
        ];

        // Preserve the specified byte from the original selector if requested
        if let Some(byte_index) = preserve_byte_index {
            if (byte_index as usize) < 4 {
                candidate_bytes[byte_index as usize] = selector_bytes[byte_index as usize];
            }
        }

        let candidate = u32::from_be_bytes(candidate_bytes);

        // Ensure the token doesn't collide with the original selector
        if candidate == selector {
            selector_collision_count += 1;
            continue;
        }

        // Additional checks to ensure token won't cause runtime issues
        // Avoid tokens that are all zeros or all ones (could cause issues with stack/jumps)
        if candidate == 0x00000000 || candidate == 0xFFFFFFFF {
            continue;
        }

        // Avoid tokens with repeating bytes (could create problematic patterns)
        let bytes = candidate_bytes;
        if bytes[0] == bytes[1] && bytes[1] == bytes[2] && bytes[2] == bytes[3] {
            continue;
        }

        // Ensure the token is unique among all derived tokens
        if used_tokens.insert(candidate) {
            if counter > 100 || collision_count > 10 {
                tracing::debug!(
                    "Token generation for 0x{:08x}: found after {} attempts ({} collisions, {} selector collisions)",
                    selector,
                    counter + 1,
                    collision_count,
                    selector_collision_count
                );
            }
            return Ok(candidate);
        } else {
            collision_count += 1;
        }
    }

    // If we exhausted attempts, provide detailed error information
    let preserve_info = preserve_byte_index
        .map(|idx| {
            format!(
                " (preserving byte[{}]=0x{:02x})",
                idx, selector_bytes[idx as usize]
            )
        })
        .unwrap_or_default();

    Err(Error::Generic(format!(
        "dispatcher: failed to derive unique token for selector 0x{:08x}{} after {} attempts ({} collisions, {} selector collisions)",
        selector, preserve_info, MAX_ATTEMPTS, collision_count, selector_collision_count
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::seed::Seed;

    #[test]
    fn test_generate_tokens_unique() {
        let seed = Seed::generate();
        let selectors = vec![
            FunctionSelector {
                selector: 0xa9059cbb, // transfer
                instruction_index: 0,
                target_address: 0x100,
            },
            FunctionSelector {
                selector: 0x23b872dd, // transferFrom
                instruction_index: 10,
                target_address: 0x200,
            },
            FunctionSelector {
                selector: 0x095ea7b3, // approve
                instruction_index: 20,
                target_address: 0x300,
            },
        ];

        let preserve_bytes = HashMap::new();
        let mapping =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        assert_eq!(mapping.len(), 3);

        // Check all tokens are 4 bytes
        for token in mapping.values() {
            assert_eq!(token.len(), 4);
        }

        // Check all tokens are unique
        let token_values: Vec<u32> = mapping
            .values()
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect();
        let unique_tokens: HashSet<_> = token_values.iter().collect();
        assert_eq!(unique_tokens.len(), token_values.len());

        // Check no token matches its original selector
        for (selector, token_bytes) in &mapping {
            let token = u32::from_be_bytes([
                token_bytes[0],
                token_bytes[1],
                token_bytes[2],
                token_bytes[3],
            ]);
            assert_ne!(token, *selector);
        }
    }

    #[test]
    fn test_empty_selectors() {
        let selectors = vec![];
        let preserve_bytes = HashMap::new();
        let seed = Seed::generate();
        let mapping =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        assert!(mapping.is_empty());
    }

    #[test]
    fn test_tokens_with_byte_preservation() {
        let seed = Seed::generate();
        let selectors = vec![
            FunctionSelector {
                selector: 0xa9059cbb,
                instruction_index: 0,
                target_address: 0x100,
            },
            FunctionSelector {
                selector: 0x23b872dd,
                instruction_index: 10,
                target_address: 0x200,
            },
            FunctionSelector {
                selector: 0x095ea7b3,
                instruction_index: 20,
                target_address: 0x300,
            },
        ];

        // Require preservation of byte[3] for all selectors
        let mut preserve_bytes = HashMap::new();
        preserve_bytes.insert(0xa9059cbb, 3);
        preserve_bytes.insert(0x23b872dd, 3);
        preserve_bytes.insert(0x095ea7b3, 3);

        let mapping =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        assert_eq!(mapping.len(), 3);

        // Verify byte preservation
        for (selector, token_bytes) in &mapping {
            let selector_bytes = selector.to_be_bytes();
            let byte_index = 3;
            assert_eq!(
                token_bytes[byte_index], selector_bytes[byte_index],
                "Token for selector 0x{:08x} didn't preserve byte[{}]",
                selector, byte_index
            );
        }

        // Verify uniqueness
        let token_values: Vec<u32> = mapping
            .values()
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect();
        let unique_tokens: HashSet<_> = token_values.iter().collect();
        assert_eq!(unique_tokens.len(), token_values.len());
    }

    #[test]
    fn test_tokens_avoid_problematic_values() {
        let seed = Seed::generate();
        let selectors = vec![
            FunctionSelector {
                selector: 0x12345678,
                instruction_index: 0,
                target_address: 0x100,
            },
            FunctionSelector {
                selector: 0xabcdef01,
                instruction_index: 10,
                target_address: 0x200,
            },
        ];

        let preserve_bytes = HashMap::new();
        let mapping =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        for (selector, token_bytes) in &mapping {
            let token = u32::from_be_bytes([
                token_bytes[0],
                token_bytes[1],
                token_bytes[2],
                token_bytes[3],
            ]);

            // Ensure token is different from selector
            assert_ne!(token, *selector);

            // Ensure token is not all zeros
            assert_ne!(token, 0x00000000, "Token should not be all zeros");

            // Ensure token is not all ones
            assert_ne!(token, 0xFFFFFFFF, "Token should not be all ones");

            // Ensure token has some entropy (not repeating pattern)
            let bytes = token_bytes;
            assert!(
                !(bytes[0] == bytes[1] && bytes[1] == bytes[2] && bytes[2] == bytes[3]),
                "Token 0x{:02x}{:02x}{:02x}{:02x} should not be a repeating byte pattern",
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3]
            );
        }
    }

    #[test]
    fn test_tokens_with_mixed_preservation() {
        let seed = Seed::generate();
        let selectors = vec![
            FunctionSelector {
                selector: 0x12345678,
                instruction_index: 0,
                target_address: 0x100,
            },
            FunctionSelector {
                selector: 0xabcdef01,
                instruction_index: 10,
                target_address: 0x200,
            },
            FunctionSelector {
                selector: 0x11223344,
                instruction_index: 20,
                target_address: 0x300,
            },
        ];

        // Preserve different bytes for different selectors
        let mut preserve_bytes = HashMap::new();
        preserve_bytes.insert(0x12345678, 0); // Preserve byte[0] = 0x12
        preserve_bytes.insert(0xabcdef01, 2); // Preserve byte[2] = 0xef

        // Third selector has no preservation constraint

        let mapping =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        assert_eq!(mapping.len(), 3);

        // Verify specific byte preservation
        let token1 = mapping.get(&0x12345678).unwrap();
        assert_eq!(token1[0], 0x12, "Should preserve byte[0]");

        let token2 = mapping.get(&0xabcdef01).unwrap();
        assert_eq!(token2[2], 0xef, "Should preserve byte[2]");

        // Verify all tokens are unique
        let token_values: Vec<u32> = mapping
            .values()
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect();
        let unique_tokens: HashSet<_> = token_values.iter().collect();
        assert_eq!(unique_tokens.len(), token_values.len());
    }

    #[test]
    fn test_invalid_byte_index() {
        let seed = Seed::generate();
        let selectors = vec![FunctionSelector {
            selector: 0x12345678,
            instruction_index: 0,
            target_address: 0x100,
        }];

        // Try to preserve an invalid byte index (>= 4)
        let mut preserve_bytes = HashMap::new();
        preserve_bytes.insert(0x12345678, 5); // Invalid index

        let result = generate_selector_token_mapping(&selectors, &seed, &preserve_bytes);

        assert!(result.is_err(), "Should fail with invalid byte index");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid byte_index"),
            "Error message should mention invalid byte_index"
        );
    }

    #[test]
    fn test_token_byte_extraction_compatibility() {
        // This test verifies that generated tokens will actually pass through
        // the byte extraction logic in controllers correctly
        let seed = Seed::generate();

        let selectors = vec![
            FunctionSelector {
                selector: 0xa9059cbb, // transfer
                instruction_index: 0,
                target_address: 0x100,
            },
            FunctionSelector {
                selector: 0x23b872dd, // transferFrom
                instruction_index: 10,
                target_address: 0x200,
            },
            FunctionSelector {
                selector: 0x095ea7b3, // approve
                instruction_index: 20,
                target_address: 0x300,
            },
        ];

        // Simulate the blueprint pattern: different byte indices for different selectors
        let mut preserve_bytes = HashMap::new();
        preserve_bytes.insert(0xa9059cbb, 0); // Tier 1: byte[0]
        preserve_bytes.insert(0x23b872dd, 2); // Tier 2: byte[2]
        preserve_bytes.insert(0x095ea7b3, 3); // Tier 3: byte[3]

        let mapping =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        // For each selector, verify the token would pass the byte extraction check
        for selector_obj in &selectors {
            let selector = selector_obj.selector;
            let token_bytes = mapping.get(&selector).unwrap();
            let token = u32::from_be_bytes([
                token_bytes[0],
                token_bytes[1],
                token_bytes[2],
                token_bytes[3],
            ]);

            let byte_index = preserve_bytes.get(&selector).unwrap();
            let selector_bytes = selector.to_be_bytes();
            let token_bytes_arr = token.to_be_bytes();

            // Verify the byte at the specified index matches
            assert_eq!(
                selector_bytes[*byte_index as usize], token_bytes_arr[*byte_index as usize],
                "Token 0x{:08x} for selector 0x{:08x} must preserve byte[{}]=0x{:02x}",
                token, selector, byte_index, selector_bytes[*byte_index as usize]
            );

            // Simulate the EVM BYTE opcode behavior:
            // BYTE(i, x) extracts the i-th byte from x (0 = most significant)
            // This is what the controller does: BYTE(byte_index, CALLDATALOAD(0))
            // where CALLDATALOAD(0) loads the token (padded to 32 bytes)

            // In the actual controller, we do:
            // 1. CALLDATALOAD(0) - loads 32 bytes with token in first 4 bytes
            // 2. BYTE(byte_index) - extracts the byte at index
            // 3. PUSH(expected_byte) - pushes the expected byte from selector
            // 4. EQ - compares them

            // The token will be padded to 32 bytes when loaded via CALLDATALOAD
            // Bytes 0-3: token
            // Bytes 4-31: zeros (or argument data)

            // Since byte_index is 0-3, we're extracting from the token portion
            let extracted_byte = token_bytes_arr[*byte_index as usize];
            let expected_byte = selector_bytes[*byte_index as usize];

            assert_eq!(
                extracted_byte, expected_byte,
                "Byte extraction simulation failed: token 0x{:08x} byte[{}]=0x{:02x} != expected 0x{:02x}",
                token, byte_index, extracted_byte, expected_byte
            );
        }
    }

    #[test]
    fn test_deterministic_secret_from_seed() {
        // This test verifies that using the same seed always produces the same mapping
        let seed = Seed::generate();

        let selectors = vec![
            FunctionSelector {
                selector: 0xa9059cbb,
                instruction_index: 0,
                target_address: 0x100,
            },
            FunctionSelector {
                selector: 0x23b872dd,
                instruction_index: 10,
                target_address: 0x200,
            },
        ];
        let preserve_bytes = HashMap::new();

        let mapping_a =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();
        let mapping_b =
            generate_selector_token_mapping(&selectors, &seed, &preserve_bytes).unwrap();

        assert_eq!(mapping_a, mapping_b, "Same seed should produce same mapping");
    }
}
