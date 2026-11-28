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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerdeCodeChange"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
    /// EIP-8298 adoption, referring to code already available in state.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", alias = "codeHash")
    )]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    new_code_hash: Option<B256>,
    /// Lazily computed hash of the immutable code bytes.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "borsh", borsh(skip))]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    hash: OnceLock<B256>,
}
impl CodeChange {
    /// Creates a new [`CodeChange`].
    pub const fn new(block_access_index: BlockAccessIndex, new_code: Bytes) -> Self {
        Self { block_access_index, new_code, new_code_hash: None, hash: OnceLock::new() }
    }

    /// Creates a hash-only code adoption as specified by EIP-8298.
    pub const fn new_hash(block_access_index: BlockAccessIndex, code_hash: B256) -> Self {
        Self {
            block_access_index,
            new_code: Bytes::new(),
            new_code_hash: Some(code_hash),
            hash: OnceLock::new(),
        }
    }

    /// Returns the adopted hash, or `None` for code installed as bytecode.
    pub const fn adopted_code_hash(&self) -> Option<B256> {
        self.new_code_hash
    }

    /// Returns the bal index.
    #[inline]
    pub const fn block_access_index(&self) -> BlockAccessIndex {
        self.block_access_index
    }

    /// Returns the new code.
    #[inline]
    pub const fn new_code(&self) -> &Bytes {
        &self.new_code
    }

    /// Consumes the change and returns the new code.
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

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SerdeCodeChange {
    #[serde(rename = "index", alias = "blockAccessIndex", alias = "txIndex")]
    block_access_index: BlockAccessIndex,
    #[serde(rename = "code", alias = "newCode")]
    new_code: Bytes,
    #[serde(default, alias = "codeHash")]
    new_code_hash: Option<B256>,
}

#[cfg(feature = "serde")]
impl TryFrom<SerdeCodeChange> for CodeChange {
    type Error = &'static str;

    fn try_from(value: SerdeCodeChange) -> Result<Self, Self::Error> {
        if let Some(hash) = value.new_code_hash {
            if !value.new_code.is_empty() {
                return Err("code adoption must not contain bytecode");
            }
            Ok(Self::new_hash(value.block_access_index, hash))
        } else {
            Ok(Self::new(value.block_access_index, value.new_code))
        }
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for CodeChange {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let index = BlockAccessIndex::deserialize_reader(reader)?;
        let code = Bytes::deserialize_reader(reader)?;
        let hash = Option::<B256>::deserialize_reader(reader)?;
        if let Some(hash) = hash {
            if !code.is_empty() {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "code adoption must not contain bytecode",
                ));
            }
            Ok(Self::new_hash(index, hash))
        } else {
            Ok(Self::new(index, code))
        }
    }
}

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
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if buf.len() < header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let (mut payload, remainder) = buf.split_at(header.payload_length);
        let index = BlockAccessIndex::decode(&mut payload)?;
        let code = Bytes::decode(&mut payload)?;
        let change = if payload.is_empty() {
            Self::new(index, code)
        } else {
            let hash = B256::decode(&mut payload)?;
            if !code.is_empty() || !payload.is_empty() {
                return Err(alloy_rlp::Error::Custom("invalid code adoption"));
            }
            Self::new_hash(index, hash)
        };
        *buf = remainder;
        Ok(change)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes;

    #[cfg(feature = "rlp")]
    #[test]
    fn hash_adoption_rlp_preserves_hash_and_remainder() {
        use alloy_rlp::{Decodable, Encodable};
        let change = CodeChange::new_hash(BlockAccessIndex::new(3), B256::repeat_byte(0x42));
        let mut encoded = alloy_rlp::encode(&change);
        assert_eq!(encoded.len(), change.length());
        encoded.push(0x7f);
        let mut input = encoded.as_slice();
        assert_eq!(CodeChange::decode(&mut input).unwrap(), change);
        assert_eq!(input, &[0x7f]);
        assert_eq!(change.code_hash(), B256::repeat_byte(0x42));
        let mut mixed = alloy_rlp::encode(&change);
        mixed[2] = 0x00;
        assert!(CodeChange::decode(&mut mixed.as_slice()).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn hash_adoption_serde_rejects_bytecode() {
        let change = CodeChange::new_hash(BlockAccessIndex::new(3), B256::repeat_byte(0x42));
        let mut value = serde_json::to_value(&change).unwrap();
        assert_eq!(serde_json::from_value::<CodeChange>(value.clone()).unwrap(), change);
        value["code"] = serde_json::Value::String("0x00".into());
        assert!(serde_json::from_value::<CodeChange>(value).is_err());
    }

    #[cfg(feature = "borsh")]
    #[test]
    fn hash_adoption_borsh_roundtrip_rejects_mixed_payload() {
        let change = CodeChange::new_hash(BlockAccessIndex::new(3), B256::repeat_byte(0x42));
        let encoded = borsh::to_vec(&change).unwrap();
        assert_eq!(borsh::from_slice::<CodeChange>(&encoded).unwrap(), change);
        let mixed =
            borsh::to_vec(&(change.block_access_index, bytes!("00"), change.adopted_code_hash()))
                .unwrap();
        assert!(borsh::from_slice::<CodeChange>(&mixed).is_err());
    }

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
            borsh::to_vec(&(
                change.block_access_index,
                change.new_code(),
                change.adopted_code_hash()
            ))
            .unwrap()
        );
        let decoded: CodeChange = borsh::from_slice(&encoded).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
    }
}
