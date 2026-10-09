use crate::result::Error;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// The deterministic byte stream used by Azoth's transformation protocol.
///
/// This alias deliberately names a pinned algorithm instead of `rand::rngs::StdRng`, whose
/// implementation is allowed to change between `rand` releases. Changing this algorithm or the
/// pinned `rand_chacha` or `rand` version is a protocol change: bump the pipeline profile and
/// update the golden vectors in this module.
pub type DeterministicRng = ChaCha20Rng;

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
    pub fn create_deterministic_rng(&self) -> DeterministicRng {
        self.derive_rng(b"AZOTH_DEFAULT_STREAM_V3")
    }

    /// Creates an independent deterministic RNG stream for a domain label.
    ///
    /// All 256 derived bits seed the generator. Callers should include the normalized input hash,
    /// profile version, transform identifier, occurrence, and decision label in `domain` when
    /// choices must remain isolated from unrelated passes.
    pub fn derive_rng(&self, domain: &[u8]) -> DeterministicRng {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AZOTH_RNG_STREAM_V3_CHACHA20");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update(self.inner);
        DeterministicRng::from_seed(hasher.finalize().into())
    }

    /// Derives a domain-separated 256-bit child seed.
    pub fn derive_seed(&self, domain: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AZOTH_CHILD_SEED_V2");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update(self.inner);
        Self {
            inner: hasher.finalize().into(),
        }
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

    /// Create from raw 32-byte array (useful for fuzzing)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicRng, Seed};
    use crate::result::Error;
    use rand::{RngCore, SeedableRng};
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
        let domain = b"AZOTH_DEFAULT_STREAM_V3";
        hasher.update(b"AZOTH_RNG_STREAM_V3_CHACHA20");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update(seed.inner);
        let mut manual_rng = DeterministicRng::from_seed(hasher.finalize().into());

        for _ in 0..4 {
            assert_eq!(rng.next_u64(), manual_rng.next_u64());
        }
    }

    #[test]
    fn rng_domains_and_high_seed_bits_are_effective() {
        let low = Seed::from_bytes([0u8; 32]);
        let mut high_bytes = [0u8; 32];
        high_bytes[31] = 1;
        let high = Seed::from_bytes(high_bytes);

        assert_ne!(
            low.derive_rng(b"pass-a").next_u64(),
            high.derive_rng(b"pass-a").next_u64()
        );
        assert_ne!(
            low.derive_rng(b"pass-a").next_u64(),
            low.derive_rng(b"pass-b").next_u64()
        );
    }

    #[test]
    fn rng_stream_has_a_fixed_golden_vector() {
        let seed = Seed::from_hex(SAMPLE_HEX).expect("valid sample seed");
        let mut rng = seed.derive_rng(b"azoth/golden/domain/v1");
        let mut output = [0u8; 64];
        rng.fill_bytes(&mut output);

        assert_eq!(
            hex::encode(output),
            "12d541e3dd62ec6e96e5ce09b90eccc3be2de3f566877362afabdb66d4c5532a\
             e09d49b187c3d31cdcfd2961a0540ecf6907017e8721c2e1a130fd7c7809f664"
        );
    }
}
