//! Contains the [`CodeChange`] struct, which represents a new code for an account.
//! Single code change: `tx_index` -> `new_code`
use crate::BlockAccessIndex;
use alloy_primitives::{B256, Bytes, KECCAK256_EMPTY, keccak256};
use core::hash::{Hash, Hasher};
#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// This struct is used to track the new codes of accounts in a block.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CodeChange {
    /// The index of bal that stores this code change.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "index", alias = "blockAccessIndex", alias = "txIndex")
    )]
    pub block_access_index: BlockAccessIndex,
    /// The new code of the account.
    #[cfg_attr(feature = "serde", serde(rename = "code", alias = "newCode"))]
    new_code: Bytes,
    /// The hash of code adopted from another account instead of supplied as bytes.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    new_code_hash: Option<B256>,
    /// Lazily computed hash of the immutable code bytes.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "borsh", borsh(skip))]
    hash: OnceLock<B256>,
}
impl CodeChange {
    /// Creates a new [`CodeChange`].
    pub const fn new(block_access_index: BlockAccessIndex, new_code: Bytes) -> Self {
        Self { block_access_index, new_code, new_code_hash: None, hash: OnceLock::new() }
    }

    /// Records code adoption without repeating the adopted code bytes.
    pub const fn new_hash(block_access_index: BlockAccessIndex, new_code_hash: B256) -> Self {
        Self {
            block_access_index,
            new_code: Bytes::new(),
            new_code_hash: Some(new_code_hash),
            hash: OnceLock::new(),
        }
    }

    /// Returns the adopted code hash, or `None` when the change supplies code bytes.
    pub const fn new_code_hash(&self) -> Option<B256> {
        self.new_code_hash
    }

    /// Returns the bal index.
    #[inline]
    pub const fn block_access_index(&self) -> BlockAccessIndex {
        self.block_access_index
    }

    /// Returns the supplied code bytes, empty when the change records code adoption.
    #[inline]
    pub const fn new_code(&self) -> &Bytes {
        &self.new_code
    }

    /// Consumes the change and returns the supplied bytes, empty for code adoption.
    #[inline]
    pub fn into_code(self) -> Bytes {
        self.new_code
    }

    /// Returns the Keccak-256 hash of the new code, computing it only when needed.
    #[inline]
    pub fn code_hash(&self) -> B256 {
        if let Some(hash) = self.new_code_hash {
            return hash;
        }
        #[allow(clippy::useless_conversion)]
        *self.hash.get_or_init(|| {
            if self.new_code.is_empty() { KECCAK256_EMPTY } else { keccak256(&self.new_code) }
                .into()
        })
    }
}

impl PartialEq for CodeChange {
    fn eq(&self, other: &Self) -> bool {
        if self.block_access_index != other.block_access_index
            || self.new_code_hash != other.new_code_hash
        {
            return false;
        }
        if let (Some(hash), Some(other_hash)) = (self.hash.get(), other.hash.get())
            && hash != other_hash
        {
            return false;
        }
        // Preserve exact equality regardless of whether either cache is populated.
        self.new_code == other.new_code
    }
}

impl Eq for CodeChange {}

impl Hash for CodeChange {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_access_index.hash(state);
        self.new_code.hash(state);
        self.new_code_hash.hash(state);
    }
}

#[cfg(feature = "rlp")]
impl alloy_rlp::Encodable for CodeChange {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.block_access_index.length()
                + self.new_code.length()
                + self.new_code_hash.map_or(0, |hash| hash.length()),
        }
        .encode(out);
        self.block_access_index.encode(out);
        self.new_code.encode(out);
        if let Some(hash) = self.new_code_hash {
            hash.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.block_access_index.length()
            + self.new_code.length()
            + self.new_code_hash.map_or(0, |hash| hash.length());
        alloy_rlp::length_of_length(payload_length) + payload_length
    }
}

#[cfg(feature = "rlp")]
impl alloy_rlp::Decodable for CodeChange {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = alloy_rlp::Header::decode_bytes(buf, true)?;
        let payload_length = payload.len();
        let block_access_index = BlockAccessIndex::decode(&mut payload)?;
        let new_code = Bytes::decode(&mut payload)?;
        let new_code_hash =
            if payload.is_empty() { None } else { Some(B256::decode(&mut payload)?) };
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: payload_length,
                got: payload_length - payload.len(),
            });
        }
        match new_code_hash {
            Some(hash) => {
                if !new_code.is_empty() {
                    return Err(alloy_rlp::Error::Custom(
                        "code adoption must not contain code bytes",
                    ));
                }
                Ok(Self::new_hash(block_access_index, hash))
            }
            None => Ok(Self::new(block_access_index, new_code)),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CodeChange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Fields {
            #[serde(rename = "index", alias = "blockAccessIndex", alias = "txIndex")]
            block_access_index: BlockAccessIndex,
            #[serde(rename = "code", alias = "newCode")]
            new_code: Bytes,
            #[serde(default)]
            new_code_hash: Option<B256>,
        }
        let fields = <Fields as serde::Deserialize>::deserialize(deserializer)?;
        match fields.new_code_hash {
            Some(hash) => {
                if !fields.new_code.is_empty() {
                    return Err(serde::de::Error::custom(
                        "code adoption must not contain code bytes",
                    ));
                }
                Ok(Self::new_hash(fields.block_access_index, hash))
            }
            None => Ok(Self::new(fields.block_access_index, fields.new_code)),
        }
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for CodeChange {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let block_access_index =
            <BlockAccessIndex as borsh::BorshDeserialize>::deserialize_reader(reader)?;
        let new_code = <Bytes as borsh::BorshDeserialize>::deserialize_reader(reader)?;
        let new_code_hash = <Option<B256> as borsh::BorshDeserialize>::deserialize_reader(reader)?;
        match new_code_hash {
            Some(hash) => {
                if !new_code.is_empty() {
                    return Err(borsh::io::Error::new(
                        borsh::io::ErrorKind::InvalidData,
                        "code adoption must not contain code bytes",
                    ));
                }
                Ok(Self::new_hash(block_access_index, hash))
            }
            None => Ok(Self::new(block_access_index, new_code)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for CodeChange {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let index = u.arbitrary()?;
        if u.arbitrary()? {
            Ok(Self::new_hash(index, u.arbitrary()?))
        } else {
            Ok(Self::new(index, u.arbitrary()?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes;

    #[test]
    fn lazy_hash_and_clone() {
        for code in [Bytes::new(), bytes!("6000")] {
            let change = CodeChange::new(BlockAccessIndex::new(1), code.clone());
            let uncached = change.clone();
            assert!(change.hash.get().is_none());
            assert_eq!(change.code_hash(), keccak256(&code));
            assert_eq!(change.hash.get(), Some(&keccak256(&code)));
            assert_eq!(change, uncached);
            assert_eq!(change.clone().hash.get(), change.hash.get());
        }
    }

    #[test]
    fn equality_with_cached_hashes() {
        let a = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let b = a.clone();
        let c = CodeChange::new(BlockAccessIndex::new(1), bytes!("6001"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        a.code_hash();
        assert_eq!(a, b);
        assert_ne!(a, c);
        b.code_hash();
        c.code_hash();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, CodeChange::new(BlockAccessIndex::new(2), bytes!("6000")));
    }

    #[cfg(feature = "std")]
    #[test]
    fn concurrent_hash_and_hash_trait() {
        use std::{collections::hash_map::DefaultHasher, thread};
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let hash_value = || {
            let mut hasher = DefaultHasher::new();
            change.hash(&mut hasher);
            hasher.finish()
        };
        let before = hash_value();
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| assert_eq!(change.code_hash(), keccak256(change.new_code())));
            }
        });
        assert_eq!(hash_value(), before);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn rlp_ignores_cache() {
        use alloy_rlp::{Decodable, Encodable};
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let encoded = alloy_rlp::encode(&change);
        assert_eq!(encoded, [0xc4, 0x01, 0x82, 0x60, 0x00]);
        change.code_hash();
        assert_eq!(alloy_rlp::encode(&change), encoded);
        assert_eq!(change.length(), encoded.len());
        let decoded = CodeChange::decode(&mut encoded.as_slice()).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
        assert!(CodeChange::decode(&mut &[0xc5, 0x01, 0x82, 0x60, 0x00, 0x80][..]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_ignores_cache() {
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        change.code_hash();
        let json = serde_json::to_string(&change).unwrap();
        assert_eq!(json, r#"{"index":"0x1","code":"0x6000"}"#);
        let decoded: CodeChange = serde_json::from_str(&json).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
    }

    #[cfg(feature = "borsh")]
    #[test]
    fn borsh_ignores_cache() {
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let encoded = borsh::to_vec(&change).unwrap();
        change.code_hash();
        assert_eq!(borsh::to_vec(&change).unwrap(), encoded);
        assert_eq!(
            encoded,
            borsh::to_vec(&(change.block_access_index, change.new_code(), change.new_code_hash()))
                .unwrap()
        );
        let decoded: CodeChange = borsh::from_slice(&encoded).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn hash_adoption_rlp_preserves_legacy_and_rejects_ambiguous_changes() {
        use alloy_rlp::{Decodable, Encodable};
        let hash = B256::repeat_byte(0x42);
        let change = CodeChange::new_hash(BlockAccessIndex::new(1), hash);
        let mut expected = vec![0xe3, 0x01, 0x80, 0xa0];
        expected.extend_from_slice(hash.as_slice());
        let encoded = alloy_rlp::encode(&change);
        assert_eq!(encoded, expected);
        assert_eq!(change.length(), encoded.len());
        assert_eq!(change.code_hash(), hash);
        assert_eq!(CodeChange::decode(&mut encoded.as_slice()).unwrap(), change);
        assert_ne!(change, CodeChange::new(BlockAccessIndex::new(1), Bytes::new()));

        let mut ambiguous = vec![0xe3, 0x01, 0x01, 0xa0];
        ambiguous.extend_from_slice(hash.as_slice());
        assert_eq!(
            CodeChange::decode(&mut ambiguous.as_slice()).unwrap_err(),
            alloy_rlp::Error::Custom("code adoption must not contain code bytes")
        );
        for malformed in [&[0xc3, 0x01, 0x80, 0x80][..], &[0xc4, 0x01, 0x80, 0x01, 0x80][..]] {
            assert!(CodeChange::decode(&mut &malformed[..]).is_err());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn hash_adoption_serde_roundtrip_and_aliases() {
        let hash = B256::repeat_byte(0x42);
        let change = CodeChange::new_hash(BlockAccessIndex::new(1), hash);
        let value = serde_json::to_value(&change).unwrap();
        assert_eq!(value, serde_json::json!({"index":"0x1", "code":"0x", "newCodeHash":hash}));
        assert_eq!(serde_json::from_value::<CodeChange>(value).unwrap(), change);
        assert_eq!(
            serde_json::from_value::<CodeChange>(
                serde_json::json!({"txIndex":"0x1", "newCode":"0x", "newCodeHash":hash})
            )
            .unwrap(),
            change
        );
        assert!(
            serde_json::from_value::<CodeChange>(
                serde_json::json!({"index":"0x1", "code":"0x60", "newCodeHash":hash})
            )
            .is_err()
        );
    }

    #[cfg(feature = "borsh")]
    #[test]
    fn hash_adoption_borsh_roundtrip() {
        let change = CodeChange::new_hash(BlockAccessIndex::new(1), B256::repeat_byte(0x42));
        let encoded = borsh::to_vec(&change).unwrap();
        assert_eq!(borsh::from_slice::<CodeChange>(&encoded).unwrap(), change);
    }
}
