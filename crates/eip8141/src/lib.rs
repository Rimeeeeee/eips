//! [EIP-8141] frame types, proof claims, and the [EIP-7906] assertion mode.
//!
//! PROOF frames carry an encoded key, message, and witness in their data. A zero message
//! denotes the canonical transaction signing hash. [`ProofClaim`] borrows the witness;
//! parsing a claim does not authenticate it. Validate the frame fields and leading proof
//! prefix before executing a verifier, and trust a claim only after that call succeeds.
//!
//! Frame discriminants are decoded independently of fork activation. Consumers must select
//! the active protocol before executing them. Legacy signature utilities remain available
//! for older fixture formats; proof-frame transactions have no outer signature list.
//!
//! [EIP-7906]: https://eips.ethereum.org/EIPS/eip-7906
//! [EIP-8141]: https://eips.ethereum.org/EIPS/eip-8141
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[macro_use]
mod macros;

mod address;
pub use address::FrameAddress;

mod calldata;
pub use calldata::calldata_tokens;

mod error;
pub use error::Eip8141Error;

#[cfg(feature = "serde")]
mod serde_utils;

pub mod constants;
pub use constants::*;

mod frame;
pub use frame::*;

mod nonce;
pub use nonce::*;

mod receipt;
pub use receipt::*;

mod signature;
pub use signature::*;

mod proof;
pub use proof::*;
