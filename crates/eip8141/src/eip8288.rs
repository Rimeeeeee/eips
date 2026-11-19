//! EIP-8288 dependency declarations. Cryptographic witnesses are carried separately.

use alloy_primitives::{B256, Bytes};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use core::slice::ChunksExact;

use crate::{Frame, FrameMode};

/// Dependency verification frame mode.
pub const DEP_VERIFY_FRAME_MODE: u8 = 4;
/// Encoded size of a dependency triple.
pub const DEPENDENCY_BYTES: usize = 96;
/// Maximum declarations in one dependency frame.
pub const MAX_DEPENDENCIES_PER_FRAME: usize = 256;
/// leanSPHINCS dependency scheme.
pub const LEANSPHINCS_SCHEME: u8 = 0x10;
/// Reserved leanSTARK dependency scheme; declarations using it are currently invalid.
pub const LEANSTARK_SCHEME: u8 = 0x11;
/// Execution gas charged per leanSPHINCS declaration.
pub const LEANSPHINCS_VERIFICATION_GAS: u64 = 3_000;
/// Intrinsic proof charge per dependency declaration.
pub const LEANSTARK_VERIFICATION_GAS: u64 = 30_000;
/// Mempool aggregation interval in milliseconds.
pub const AGGREGATION_INTERVAL: u64 = 1_000;
/// Public-pool limit on distinct signature dependencies per transaction.
pub const MAX_SIGS_PER_TX: usize = 16;
/// Public-pool limit on distinct STARK dependencies per transaction.
pub const MAX_STARKS_PER_TX: usize = 1;
/// Signature dependency limit per wrapper in the current draft.
pub const MAX_LEANSIG_DEPS_PER_WRAPPER: usize = 16;
/// STARK dependency limit per wrapper in the current draft.
pub const MAX_LEANSTARK_DEPS_PER_WRAPPER: usize = 1;

/// The EIP-8288 block header entry; the dependency list is reconstructed from transactions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct RecursiveStark {
    /// Serialized recursive proof, empty exactly when there are no dependencies.
    pub stark_proof: Bytes,
    /// Digest of the sorted, distinct dependencies of the block.
    pub block_deps_hash: B256,
}

/// A declaration, or a resolved dependency after replacing a zero message hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Dependency {
    /// Verification scheme; currently only [`LEANSPHINCS_SCHEME`] is accepted.
    pub scheme: u8,
    /// Message digest, with zero denoting the containing transaction's signing hash.
    pub data_hash: B256,
    /// For leanSPHINCS, the public key `PK.seed || PK.root` itself.
    pub verification_key_hash: B256,
}

impl Dependency {
    /// Encodes the padded scheme word followed by the two 32-byte fields.
    pub fn encode(self) -> [u8; DEPENDENCY_BYTES] {
        let mut encoded = [0; DEPENDENCY_BYTES];
        encoded[31] = self.scheme;
        encoded[32..64].copy_from_slice(self.data_hash.as_slice());
        encoded[64..].copy_from_slice(self.verification_key_hash.as_slice());
        encoded
    }

    /// Replaces the zero-message sentinel without changing the transaction's frame bytes.
    pub fn resolve(mut self, signature_hash: B256) -> Self {
        if self.data_hash.is_zero() {
            self.data_hash = signature_hash;
        }
        self
    }
}

/// A malformed or currently unsupported dependency declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DependencyError {
    /// The containing frame list exceeds EIP-8141's bound.
    #[error("too many EIP-8141 frames")]
    FrameCount,
    /// Payload must contain one to 256 complete triples.
    #[error("invalid EIP-8288 dependency payload length: {0}")]
    Length(usize),
    /// The scheme word's leading 31 bytes must be zero.
    #[error("nonzero EIP-8288 scheme padding")]
    Padding,
    /// The scheme is unknown or reserved.
    #[error("unsupported EIP-8288 scheme: {0}")]
    Scheme(u8),
    /// Dependency frames require an absent target and zero value, flags and state gas.
    #[error("invalid EIP-8288 dependency frame fields")]
    FrameFields,
    /// A dependency frame must not be an atomic batch member or terminator.
    #[error("EIP-8288 dependency frame is in an atomic batch")]
    AtomicBatch,
    /// The execution limit must equal the declaration verification charge.
    #[error("invalid EIP-8288 dependency execution gas limit")]
    ExecutionGas,
}

/// Allocation-free parsing of bounded dependency-frame data.
#[derive(Clone, Debug)]
pub struct DependencyIter<'a>(ChunksExact<'a, u8>);

impl<'a> DependencyIter<'a> {
    /// Checks payload bounds before reading declarations; each item validates its scheme word.
    pub fn new(data: &'a [u8]) -> Result<Self, DependencyError> {
        if data.is_empty()
            || data.len() > DEPENDENCY_BYTES * MAX_DEPENDENCIES_PER_FRAME
            || !data.len().is_multiple_of(DEPENDENCY_BYTES)
        {
            return Err(DependencyError::Length(data.len()));
        }
        Ok(Self(data.chunks_exact(DEPENDENCY_BYTES)))
    }

    /// Checks frame fields and returns its declarations. Consume every item to validate them.
    pub fn from_frame(frame: &'a Frame, previous_atomic: bool) -> Result<Self, DependencyError> {
        if frame.mode != FrameMode::DependencyVerify
            || !frame.target.is_empty()
            || !frame.value.is_zero()
            || frame.flags != 0
            || frame.limits.state != 0
        {
            return Err(DependencyError::FrameFields);
        }
        if previous_atomic {
            return Err(DependencyError::AtomicBatch);
        }
        let dependencies = Self::new(&frame.data)?;
        if frame.limits.execution != dependencies.len() as u64 * LEANSPHINCS_VERIFICATION_GAS {
            return Err(DependencyError::ExecutionGas);
        }
        Ok(dependencies)
    }
}

impl Iterator for DependencyIter<'_> {
    type Item = Result<Dependency, DependencyError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|data| {
            if data[..31].iter().any(|byte| *byte != 0) {
                return Err(DependencyError::Padding);
            }
            if data[31] != LEANSPHINCS_SCHEME {
                return Err(DependencyError::Scheme(data[31]));
            }
            Ok(Dependency {
                scheme: data[31],
                data_hash: B256::from_slice(&data[32..64]),
                verification_key_hash: B256::from_slice(&data[64..]),
            })
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for DependencyIter<'_> {}

/// Checks all dependency-frame fields and declarations, including the preceding batch flag.
pub fn validate_dependency_frame(
    frame: &Frame,
    previous_atomic: bool,
) -> Result<(), DependencyError> {
    for dependency in DependencyIter::from_frame(frame, previous_atomic)? {
        dependency?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FrameLimits;
    use alloy_primitives::{Address, Bytes};

    fn declaration() -> Dependency {
        Dependency {
            scheme: LEANSPHINCS_SCHEME,
            data_hash: B256::ZERO,
            verification_key_hash: B256::repeat_byte(7),
        }
    }

    fn frame() -> Frame {
        Frame {
            mode: FrameMode::DependencyVerify,
            limits: FrameLimits { execution: LEANSPHINCS_VERIFICATION_GAS, state: 0 },
            data: Bytes::copy_from_slice(&declaration().encode()),
            ..Default::default()
        }
    }

    #[test]
    fn encoding_and_resolution() {
        let bytes = declaration().encode();
        assert_eq!(DependencyIter::new(&bytes).unwrap().next(), Some(Ok(declaration())));
        let hash = B256::repeat_byte(1);
        assert_eq!(declaration().resolve(hash).data_hash, hash);
        assert_eq!(declaration().resolve(hash).resolve(B256::repeat_byte(2)).data_hash, hash);
        assert_eq!(declaration().data_hash, B256::ZERO);
    }

    #[test]
    fn rejects_malformed_and_reserved_declarations() {
        for length in [0, 95, 97, DEPENDENCY_BYTES * (MAX_DEPENDENCIES_PER_FRAME + 1)] {
            assert_eq!(
                DependencyIter::new(&alloc::vec![0; length]).unwrap_err(),
                DependencyError::Length(length)
            );
        }
        let mut bytes = declaration().encode();
        bytes[0] = 1;
        assert_eq!(
            DependencyIter::new(&bytes).unwrap().next(),
            Some(Err(DependencyError::Padding))
        );
        bytes[0] = 0;
        for scheme in [0, LEANSTARK_SCHEME, 255] {
            bytes[31] = scheme;
            assert_eq!(
                DependencyIter::new(&bytes).unwrap().next(),
                Some(Err(DependencyError::Scheme(scheme)))
            );
        }
    }

    #[test]
    fn enforces_frame_fields_and_batch_boundary() {
        let valid = frame();
        assert_eq!(validate_dependency_frame(&valid, false), Ok(()));
        assert_eq!(validate_dependency_frame(&valid, true), Err(DependencyError::AtomicBatch));
        let mut invalid = valid.clone();
        invalid.target = Address::ZERO.into();
        assert_eq!(validate_dependency_frame(&invalid, false), Err(DependencyError::FrameFields));
        for mutate in [
            |frame: &mut Frame| frame.flags = 1,
            |frame: &mut Frame| frame.value = alloy_primitives::U256::from(1),
            |frame: &mut Frame| frame.limits.state = 1,
            |frame: &mut Frame| frame.mode = FrameMode::Default,
        ] {
            let mut invalid = valid.clone();
            mutate(&mut invalid);
            assert_eq!(
                validate_dependency_frame(&invalid, false),
                Err(DependencyError::FrameFields)
            );
        }
        let mut invalid = valid;
        invalid.limits.execution += 1;
        assert_eq!(validate_dependency_frame(&invalid, false), Err(DependencyError::ExecutionGas));
    }

    #[test]
    fn accepts_maximum_frame_and_charges_duplicates() {
        let mut frame = frame();
        frame.data = declaration().encode().repeat(MAX_DEPENDENCIES_PER_FRAME).into();
        frame.limits.execution = MAX_DEPENDENCIES_PER_FRAME as u64 * LEANSPHINCS_VERIFICATION_GAS;
        assert_eq!(validate_dependency_frame(&frame, false), Ok(()));
        assert_eq!(DependencyIter::new(&frame.data).unwrap().len(), MAX_DEPENDENCIES_PER_FRAME);
    }
}
