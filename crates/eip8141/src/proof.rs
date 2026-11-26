//! Borrowed proof claims and leading-prefix validation.

use crate::{Eip8141Error, Frame, PROOF_CLAIM_LENGTH};
use alloy_primitives::B256;

/// A claim's encoded key and message together with its unmodified proof bytes.
///
/// A zero message denotes the transaction's canonical signing hash. Parsing does not
/// authenticate a claim: it is verified only after its verifier call succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofClaim<'a> {
    /// Signer or program key. A valid proof frame requires a nonzero key.
    pub key: B256,
    /// Encoded message; zero denotes the canonical signing hash.
    pub msg: B256,
    /// Bytes passed to the verifier after the key and resolved message.
    pub proof: &'a [u8],
}

impl<'a> ProofClaim<'a> {
    /// Parses the 64-byte claim prefix, returning `None` when the data is shorter.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let claim = data.get(..PROOF_CLAIM_LENGTH)?;
        Some(Self {
            key: B256::from_slice(&claim[..32]),
            msg: B256::from_slice(&claim[32..]),
            proof: &data[PROOF_CLAIM_LENGTH..],
        })
    }

    /// Resolves a zero encoded message without changing the introspectable claim.
    pub fn resolved_message(self, signature_hash: B256) -> B256 {
        if self.msg.is_zero() { signature_hash } else { self.msg }
    }
}

/// Validates every proof frame and requires them to form a leading prefix.
///
/// Returns the number of proof frames, including zero. It does not execute verifiers.
pub fn validate_proof_prefix(frames: &[Frame]) -> Result<usize, Eip8141Error> {
    let count = frames.iter().take_while(|frame| frame.mode.is_proof()).count();
    for frame in &frames[..count] {
        frame.validate_proof_fields()?;
    }
    if frames[count..].iter().any(|frame| frame.mode.is_proof()) {
        return Err(Eip8141Error::InvalidProof("proof frames must form a leading prefix"));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameMode, PROOF_COMMIT_FLAG, PROOF_READ_FLAG};
    use alloy_primitives::{Bytes, U256};

    fn proof(flags: u8, explicit: bool) -> Frame {
        let mut data = vec![0; 67];
        data[0] = 1;
        data[32] = u8::from(explicit);
        Frame { mode: FrameMode::Proof, flags, data: Bytes::from(data), ..Default::default() }
    }

    #[test]
    fn proof_claim_parsing_and_message_resolution() {
        assert_eq!(ProofClaim::parse(&[0; 63]), None);
        let frame = proof(0, false);
        let claim = frame.proof().unwrap();
        assert_eq!(claim.proof, &[0, 0, 0]);
        let hash = B256::repeat_byte(7);
        assert_eq!(claim.resolved_message(hash), hash);
        assert_eq!(claim.msg, B256::ZERO);
        let frame = proof(0, true);
        let claim = frame.proof().unwrap();
        assert_eq!(claim.resolved_message(hash), claim.msg);
    }

    #[test]
    fn mode_four_roundtrips_and_other_unknown_modes_are_rejected() {
        let frame = proof(0, false);
        let encoded = alloy_rlp::encode(&frame);
        assert_eq!(alloy_rlp::decode_exact::<Frame>(&encoded).unwrap(), frame);
        assert_eq!(FrameMode::try_from_u8(4), Some(FrameMode::Proof));
        assert_eq!(FrameMode::try_from_u8(5), None);
    }

    #[test]
    fn flags_are_specific_to_the_frame_mode() {
        for flags in 0..=u8::MAX {
            let frame = proof(flags, true);
            assert_eq!(
                frame.validate_proof_fields().is_ok(),
                flags & !(PROOF_COMMIT_FLAG | PROOF_READ_FLAG) == 0
            );
            let ordinary = Frame { flags, ..Default::default() };
            assert_eq!(ordinary.has_reserved_flags(), flags & !7 != 0);
        }
    }

    #[test]
    fn proof_fields_and_prefix_are_enforced() {
        assert_eq!(validate_proof_prefix(&[]), Ok(0));
        assert_eq!(validate_proof_prefix(&[proof(0, false), Frame::default()]), Ok(1));
        assert_eq!(
            validate_proof_prefix(&[Frame::default(), proof(0, false)]),
            Err(Eip8141Error::InvalidProof("proof frames must form a leading prefix"))
        );
        assert_eq!(
            proof(PROOF_COMMIT_FLAG, false).validate_proof_fields(),
            Err(Eip8141Error::InvalidProof("committed proof requires an explicit message"))
        );
        let mut frame = proof(0, false);
        frame.value = U256::from(1);
        assert_eq!(
            frame.validate_proof_fields(),
            Err(Eip8141Error::InvalidProof("value and state gas must be zero"))
        );
        frame.value = U256::ZERO;
        frame.limits.state = 1;
        assert_eq!(
            frame.validate_proof_fields(),
            Err(Eip8141Error::InvalidProof("value and state gas must be zero"))
        );
        frame.limits.state = 0;
        frame.data = Bytes::from(vec![0; 64]);
        assert_eq!(
            frame.validate_proof_fields(),
            Err(Eip8141Error::InvalidProof("key must be nonzero"))
        );
    }
}
