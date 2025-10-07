use azoth_core::seed::Seed;
use rand::RngCore;

#[test]
fn test_deterministic_rng() {
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();

    let mut rng1 = seed.create_deterministic_rng();
    let mut rng2 = seed.create_deterministic_rng();

    // Should produce identical sequences
    assert_eq!(rng1.next_u32(), rng2.next_u32());
    assert_eq!(rng1.next_u64(), rng2.next_u64());
}

#[test]
fn test_hash_deterministic() {
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let hash1 = seed.hash();
    let hash2 = seed.hash();
    assert_eq!(hash1, hash2);

    let hash_hex = seed.hash_hex();
    assert!(hash_hex.starts_with("0x"));
    assert_eq!(hash_hex.len(), 66); // 0x + 64 hex chars
}

#[test]
fn test_different_seeds_different_rngs() {
    let seed1 =
        Seed::from_hex("0x1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let seed2 =
        Seed::from_hex("0x2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();

    let mut rng1 = seed1.create_deterministic_rng();
    let mut rng2 = seed2.create_deterministic_rng();

    // Different seeds should produce different random sequences
    assert_ne!(rng1.next_u32(), rng2.next_u32());
}
