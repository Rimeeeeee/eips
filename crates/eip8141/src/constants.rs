//! [EIP-8141] constants.
//!
//! [EIP-8141]: https://eips.ethereum.org/EIPS/eip-8141

use alloy_primitives::{Address, U256, hex};

/// Identifier for EIP-8141 frame transactions.
pub const FRAME_TX_TYPE: u8 = 0x06;

/// Intrinsic gas cost for an EIP-8141 frame transaction.
pub const FRAME_TX_INTRINSIC_COST: u64 = 12_000;

/// Fixed gas cost charged per frame.
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;

/// Cost of a nonzero-value frame with an explicit target other than the sender.
///
/// This is EIP-2780's `TX_VALUE_COST`, referenced by EIP-8141.
pub const TX_VALUE_COST: u64 = 6_000;

/// Standard gas charged per frame transaction calldata token.
///
/// This matches `GasCosts.TX_DATA_TOKEN_STANDARD` in the execution-specs EIP-8141 draft.
pub const FRAME_TX_DATA_TOKEN_STANDARD_COST: u64 = 4;

/// Total-cost floor charged per frame transaction calldata token.
///
/// EIP-7976 raises this from 10 to 16 and counts every calldata byte as four
/// floor tokens, producing a uniform 64 gas floor per byte.
pub const FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN: u64 = 16;

/// Protocol entry point caller used by `DEFAULT` and `VERIFY` frames.
pub const ENTRY_POINT: Address = Address::new(hex!("00000000000000000000000000000000000000aa"));

/// Address of the canonical expiry verifier, deployed as an ordinary contract.
pub const EXPIRY_VERIFIER: Address = Address::new(hex!("81413f0cF12e9b6a49B1D0439E081c577D57FfFf"));

/// Calldata length, in bytes, for expiry verifier frames.
pub const EXPIRY_DATA_LENGTH: usize = 8;

/// Maximum number of frames in a frame transaction.
pub const MAX_FRAMES: usize = 64;

/// Order of the secp256k1 curve used by EIP-8141 signatures.
pub const SECP256K1N: U256 =
    U256::from_be_bytes(hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));

/// Order of the NIST P-256 curve used by EIP-8141 signatures.
pub const SECP256R1N: U256 =
    U256::from_be_bytes(hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));

/// Byte length of a secp256k1 signature entry: `v || r || s`.
pub const SECP256K1_SIGNATURE_LENGTH: usize = 65;

/// Byte length of a P-256 signature entry: `r || s || qx || qy`.
pub const P256_SIGNATURE_LENGTH: usize = 128;

/// Maximum validation work for public mempool admission.
pub const MAX_VERIFY_GAS: u64 = 100_000;

/// Maximum state gas budget across a public-mempool validation prefix.
pub const MAX_VERIFY_STATE_GAS: u64 = 500_000;

/// Maximum pending public-mempool transactions using any non-canonical paymaster.
pub const MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER: usize = 1;

/// Canonical expiry verifier runtime bytecode.
pub const EXPIRY_VERIFIER_RUNTIME: [u8; 26] =
    hex!("60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd");

/// Approval flag mask for extracting the allowed approval scope from frame flags.
pub const APPROVE_SCOPE_MASK: u8 = 0x03;

/// Atomic batch frame flag.
pub const ATOMIC_BATCH_FLAG: u8 = 0x04;

/// Mask of flag bits permitted on ordinary, non-proof frames.
pub const FRAME_FLAGS_MASK: u8 = APPROVE_SCOPE_MASK | ATOMIC_BATCH_FLAG;

/// Commit to a proof's digest in the canonical signing hash.
pub const PROOF_COMMIT_FLAG: u8 = 0x08;

/// Allow VERIFY frames to read a proof frame's encoded data.
pub const PROOF_READ_FLAG: u8 = 0x10;

/// Flags permitted on PROOF frames.
pub const PROOF_FLAGS_MASK: u8 = PROOF_COMMIT_FLAG | PROOF_READ_FLAG;

/// Byte length of the key and encoded message preceding a proof.
pub const PROOF_CLAIM_LENGTH: usize = 64;

/// Byte length of a leanSPHINCS public key.
pub const LEANSPHINCS_PUBLIC_KEY_LENGTH: usize = 32;

/// Byte length of a leanSPHINCS signature at the draft's pinned EthLib revision.
pub const LEANSPHINCS_SIGNATURE_LENGTH: usize = 7_740;

/// Provisional Bogotá Devnet 3 address; the draft leaves verifier assignments TBD.
pub const SECP256K1_VERIFIER: Address =
    Address::new(hex!("0000000000000000000000000000000000000012"));

/// Provisional Bogotá Devnet 3 address; the draft leaves verifier assignments TBD.
pub const P256_VERIFIER: Address = Address::new(hex!("0000000000000000000000000000000000000013"));

/// Provisional Bogotá Devnet 3 address; the draft leaves verifier assignments TBD.
pub const LEANSPHINCS_VERIFIER: Address =
    Address::new(hex!("0000000000000000000000000000000000000014"));
