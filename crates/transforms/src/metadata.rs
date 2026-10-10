//! Solidity metadata diversification.
//!
//! Reusing the compiler-emitted IPFS/Swarm digest across every seed creates a
//! perfect family-level linking tag.  This helper deterministically replaces only
//! the content digest while retaining the original CBOR envelope and compiler
//! version.  The result remains structurally ordinary Solidity metadata, but its
//! content address is intentionally non-resolving and must not be presented as a
//! source-verification pointer.

use azoth_core::detection::SectionKind;
use azoth_core::strip::CleanReport;
use sha3::{Digest, Keccak256};

/// Diversifies recognized metadata content hashes in-place.
///
/// Returns the number of 32-byte digests replaced. Unknown metadata layouts are
/// left untouched so malformed CBOR is never emitted.
pub fn diversify_metadata(report: &mut CleanReport, seed: &[u8; 32]) -> usize {
    let mut changed = 0usize;
    for removed in &mut report.removed {
        if !matches!(removed.kind, SectionKind::Auxdata) {
            continue;
        }
        let mut data = removed.data.to_vec();
        let original = data.clone();

        let digest_start = find_ipfs_digest(&data).or_else(|| find_swarm_digest(&data));
        let Some(start) = digest_start else {
            continue;
        };
        if start + 32 > data.len().saturating_sub(2) {
            continue;
        }

        let mut hasher = Keccak256::new();
        hasher.update(b"AZOTH_METADATA_CONTENT_DIGEST_V1");
        hasher.update(seed);
        hasher.update(&original);
        let digest: [u8; 32] = hasher.finalize().into();
        data[start..start + 32].copy_from_slice(&digest);
        removed.data = data.into();
        changed += 1;
    }
    changed
}

fn find_ipfs_digest(data: &[u8]) -> Option<usize> {
    // Solidity encodes an IPFS CIDv0 multihash as bytes(34): 0x12 0x20 <digest>.
    data.windows(2)
        .position(|window| window == [0x12, 0x20])
        .map(|index| index + 2)
}

fn find_swarm_digest(data: &[u8]) -> Option<usize> {
    let marker = data.windows(4).position(|window| window == b"bzzr")?;
    data[marker + 4..]
        .windows(2)
        .position(|window| window == [0x58, 0x20])
        .map(|relative| marker + 4 + relative + 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::strip::{CleanReport, Removed};
    use revm::primitives::{Bytes, B256};

    fn report(auxdata: Vec<u8>) -> CleanReport {
        CleanReport {
            runtime_layout: Vec::new(),
            removed: vec![Removed {
                offset: 0,
                kind: SectionKind::Auxdata,
                data: Bytes::from(auxdata),
            }],
            swarm_hash: None,
            bytes_saved: 0,
            clean_len: 1,
            clean_keccak: B256::ZERO,
            program_counter_mapping: Vec::new(),
        }
    }

    #[test]
    fn changes_only_ipfs_digest_and_is_deterministic() {
        let mut aux = vec![0xa2, 0x64, b'i', b'p', b'f', b's', 0x58, 0x22, 0x12, 0x20];
        aux.extend([0x44; 32]);
        aux.extend([0x64, b's', b'o', b'l', b'c', 0x43, 0, 8, 30, 0, 51]);
        let mut first = report(aux.clone());
        let mut second = report(aux.clone());
        let seed = [7u8; 32];
        assert_eq!(diversify_metadata(&mut first, &seed), 1);
        assert_eq!(diversify_metadata(&mut second, &seed), 1);
        assert_eq!(first.removed[0].data, second.removed[0].data);
        assert_eq!(&first.removed[0].data[..10], &aux[..10]);
        assert_eq!(&first.removed[0].data[42..], &aux[42..]);
        assert_ne!(&first.removed[0].data[10..42], &aux[10..42]);
    }
}
