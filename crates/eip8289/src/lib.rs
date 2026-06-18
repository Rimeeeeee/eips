//! [EIP-8289] warm-access multiset helpers.
//!
//! This crate models the WAM item set and refcounted warm-access multiset from the EIP-8289
//! draft. It intentionally does not implement the sparse Merkle tree commitment.
//!
//! [EIP-8289]: <https://eips.ethereum.org/EIPS/eip-8289>
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

mod wam;

pub use wam::*;
