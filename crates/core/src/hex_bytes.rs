//! Wrappers for representing byte buffers and fixed arrays as lowercase hexadecimal.
//!
//! These types (`HexBytes`/`HexArray`) wrap `Vec<u8>` or `[u8; N]`, providing consistent
//! serialization/deserialization to hex strings while emitting compact lowercase hex in `Debug`
//! output. They deref to slices so existing byte oriented code can continue to
//! operate without additional conversions.

use crate::normalize_hex_string;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::{Deref, DerefMut};

/// Wrapper around `Vec<u8>` that renders as contiguous lowercase hex for debug and serialization.
///
/// # Examples
///
/// ```
/// use azoth_core::HexBytes;
///
/// let bytes = HexBytes(vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(format!("{bytes:?}"), "deadbeef");
/// let roundtrip: Vec<u8> = bytes.clone().into();
/// assert_eq!(roundtrip, vec![0xde, 0xad, 0xbe, 0xef]);
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<HexBytes> for Vec<u8> {
    fn from(bytes: HexBytes) -> Self {
        bytes.0
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for HexBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for HexBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl DerefMut for HexBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexBytesVisitor;

        impl<'de> Visitor<'de> for HexBytesVisitor {
            type Value = HexBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a lowercase hex string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let normalized = normalize_hex_string(v).map_err(E::custom)?;
                let bytes = hex::decode(&normalized).map_err(E::custom)?;
                Ok(HexBytes(bytes))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(HexBytesVisitor)
    }
}

impl PartialEq<Vec<u8>> for HexBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

impl PartialEq<HexBytes> for Vec<u8> {
    fn eq(&self, other: &HexBytes) -> bool {
        self == &other.0
    }
}

/// Wrapper around `[u8; N]` that renders as contiguous lowercase hex for debug and serialization.
///
/// # Examples
///
/// ```
/// use azoth_core::HexArray;
///
/// let arr = HexArray::<4>([0xca, 0xfe, 0xba, 0xbe]);
/// assert_eq!(format!("{arr:?}"), "cafebabe");
/// let roundtrip: [u8; 4] = arr.into();
/// assert_eq!(roundtrip, [0xca, 0xfe, 0xba, 0xbe]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HexArray<const N: usize>(pub [u8; N]);

impl<const N: usize> HexArray<N> {
    pub fn into_inner(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> Default for HexArray<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> From<[u8; N]> for HexArray<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<HexArray<N>> for [u8; N] {
    fn from(array: HexArray<N>) -> Self {
        array.0
    }
}

impl<const N: usize> AsRef<[u8]> for HexArray<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const N: usize> AsMut<[u8]> for HexArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<const N: usize> Deref for HexArray<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl<const N: usize> DerefMut for HexArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

impl<const N: usize> fmt::Debug for HexArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> Serialize for HexArray<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexArray<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for HexArrayVisitor<N> {
            type Value = HexArray<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a lowercase hex string with {} bytes", N)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let normalized = normalize_hex_string(v).map_err(E::custom)?;
                let bytes = hex::decode(&normalized).map_err(E::custom)?;
                if bytes.len() != N {
                    return Err(E::custom(format!(
                        "expected {} bytes, got {}",
                        N,
                        bytes.len()
                    )));
                }
                let mut array = [0u8; N];
                array.copy_from_slice(&bytes);
                Ok(HexArray(array))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(HexArrayVisitor::<N>)
    }
}

impl<const N: usize> PartialEq<[u8; N]> for HexArray<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        &self.0 == other
    }
}

impl<const N: usize> PartialEq<HexArray<N>> for [u8; N] {
    fn eq(&self, other: &HexArray<N>) -> bool {
        self == &other.0
    }
}
