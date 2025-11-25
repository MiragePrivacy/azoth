use crate::result::Error;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A 256-bit cryptographic seed
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seed {
    /// The 256-bit seed
    inner: [u8; 32],
}

impl Seed {
    /// Generate a new random 256-bit seed
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self { inner: seed }
    }

    /// Create from hex string (with or without 0x prefix)
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        if hex.len() != 64 {
            return Err(Error::InvalidSeedLength(hex.len()));
        }

        let bytes = hex::decode(hex).map_err(|_| Error::InvalidSeedHex)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self { inner: seed })
    }

    /// Convert to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner))
    }

    /// Create a deterministic RNG for bytecode obfuscation transforms
    /// This ensures the same seed always produces identical obfuscated bytecode
    ///
    /// Basically, it uses whatever bytes are already stored in that Seed, regardless of how those
    /// bytes were created (randomly via generate(), from hex, from legacy u64, etc.).
    pub fn create_deterministic_rng(&self) -> StdRng {
        // Hash the seed to create RNG seed
        let mut hasher = Sha3_256::new();
        hasher.update(b"AZOTH_BYTECODE_OBFUSCATION");
        hasher.update(self.inner);
        let seed_hash = hasher.finalize();

        // Convert first 8 bytes to u64 for StdRng
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&seed_hash[..8]);
        let rng_seed = u64::from_le_bytes(seed_bytes);

        StdRng::seed_from_u64(rng_seed)
    }

    /// Get a hash of this seed for integrity/identification purposes
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.inner);
        hasher.finalize().into()
    }

    /// Get the hash as hex string
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash()))
    }

    /// Borrow the raw 32-byte seed.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::Seed;
    use crate::result::Error;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use sha3::{Digest, Sha3_256};

    const SAMPLE_HEX: &str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    #[test]
    fn from_hex_accepts_prefixed_and_unprefixed() {
        let prefixed = Seed::from_hex(SAMPLE_HEX).unwrap();
        let unprefixed =
            Seed::from_hex(SAMPLE_HEX.trim_start_matches("0x")).expect("unprefixed seed");

        assert_eq!(prefixed.inner, unprefixed.inner);
        assert_eq!(prefixed.to_hex(), SAMPLE_HEX);
    }

    #[test]
    fn from_hex_rejects_invalid_hex() {
        let invalid_hex = format!("0x{}g{}", "1".repeat(31), "1".repeat(32));
        let err = match Seed::from_hex(&invalid_hex) {
            Ok(_) => panic!("expected InvalidSeedHex error"),
            Err(err) => err,
        };
        assert!(matches!(err, Error::InvalidSeedHex));
    }

    #[test]
    fn deterministic_rng_matches_domain_separated_hash() {
        let seed = Seed::from_hex(SAMPLE_HEX).expect("valid sample seed");
        let mut rng = seed.create_deterministic_rng();

        let mut hasher = Sha3_256::new();
        hasher.update(b"AZOTH_BYTECODE_OBFUSCATION");
        hasher.update(seed.inner);
        let hash = hasher.finalize();
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&hash[..8]);
        let derived = u64::from_le_bytes(seed_bytes);
        let mut manual_rng = StdRng::seed_from_u64(derived);

        for _ in 0..4 {
            assert_eq!(rng.next_u64(), manual_rng.next_u64());
        }
    }
}
