//! [EIP-8289] warm-access multiset helpers.
//!
//! This crate models the WAM item set, refcounted warm-access multiset, and binary sparse Merkle
//! tree commitment from the EIP-8289 draft.
//!
//! [EIP-8289]: <https://eips.ethereum.org/EIPS/eip-8289>
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

mod smt;
mod wam;
mod wam_smt;

pub use smt::*;
pub use wam::*;
pub use wam_smt::*;
