//! Token generation for function dispatcher obfuscation.
//!
//! This module provides cryptographically-derived token generation for mapping
//! original function selectors to obfuscated tokens. The tokens maintain the same
//! byte width as original selectors to preserve dispatcher structure.

use crate::{Error, Result};
use azoth_core::detection::FunctionSelector;
use rand::rngs::StdRng;
use rand::RngCore;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};

/// Generates a mapping from original 4-byte function selectors to derived 4-byte tokens.
pub fn generate_selector_token_mapping(
    selectors: &[FunctionSelector],
    rng: &mut StdRng,
) -> Result<HashMap<u32, Vec<u8>>> {
    if selectors.is_empty() {
        return Ok(HashMap::new());
    }

    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);

    let mut mapping = HashMap::with_capacity(selectors.len());
    let mut used_tokens = HashSet::with_capacity(selectors.len());

    for selector in selectors {
        let token = derive_unique_selector_token(selector.selector, &secret, &mut used_tokens)?;
        mapping.insert(selector.selector, token.to_be_bytes().to_vec());
    }

    Ok(mapping)
}

/// Derives a unique 4-byte token for a given selector.
fn derive_unique_selector_token(
    selector: u32,
    secret: &[u8; 32],
    used_tokens: &mut HashSet<u32>,
) -> Result<u32> {
    const MAX_ATTEMPTS: u32 = 10_000;

    let selector_bytes = selector.to_be_bytes();

    for counter in 0..MAX_ATTEMPTS {
        let mut hasher = Keccak256::new();
        hasher.update(secret);
        hasher.update(selector_bytes);
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();

        // Take the last 4 bytes of the hash as the candidate token
        let candidate = u32::from_be_bytes([
            hash[hash.len() - 4],
            hash[hash.len() - 3],
            hash[hash.len() - 2],
            hash[hash.len() - 1],
        ]);

        // Ensure the token doesn't collide with the original selector
        if candidate == selector {
            continue;
        }

        // Ensure the token is unique among all derived tokens
        if used_tokens.insert(candidate) {
            return Ok(candidate);
        }
    }

    Err(Error::Generic(
        "dispatcher: failed to derive unique 4-byte selector token".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_generate_tokens_unique() {
        let mut rng = StdRng::seed_from_u64(12345);
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

        let mapping = generate_selector_token_mapping(&selectors, &mut rng).unwrap();

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
        let mut rng = StdRng::seed_from_u64(12345);
        let selectors = vec![];

        let mapping = generate_selector_token_mapping(&selectors, &mut rng).unwrap();

        assert!(mapping.is_empty());
    }
}
