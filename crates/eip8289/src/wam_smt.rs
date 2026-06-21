//! EIP-8289 adapters for the general sparse Merkle tree.

use crate::{SparseMerkleProof, SparseMerkleTree, WamItem, WamItems, WarmAccessMultiset};
use alloy_eip7928::BlockAccessList;
use alloy_primitives::B256;
use sha2::{Digest, Sha256};

/// Domain tag used by the canonical serialization of an account item.
pub const ACCOUNT_ITEM_TAG: u8 = 0;

/// Domain tag used by the canonical serialization of a storage-slot item.
pub const SLOT_ITEM_TAG: u8 = 1;

/// A WAM and its generic SMT commitment, updated atomically by EIP-8289 transitions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommittedWarmAccessMultiset {
    wam: WarmAccessMultiset,
    tree: SparseMerkleTree,
}

impl CommittedWarmAccessMultiset {
    /// Creates an empty committed WAM.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates committed state from an existing WAM.
    pub fn from_wam(wam: WarmAccessMultiset) -> Self {
        let mut tree = SparseMerkleTree::new();
        for (item, count) in wam.iter() {
            tree.update(wam_leaf_key(item), wam_leaf_value(count));
        }
        Self { wam, tree }
    }

    /// Returns the refcounted WAM.
    #[inline]
    pub const fn wam(&self) -> &WarmAccessMultiset {
        &self.wam
    }

    /// Returns the underlying general sparse Merkle tree.
    #[inline]
    pub const fn tree(&self) -> &SparseMerkleTree {
        &self.tree
    }

    /// Returns the current WAM root.
    #[inline]
    pub fn root(&self) -> B256 {
        self.tree.root()
    }

    /// Returns a proof for a WAM item.
    #[inline]
    pub fn prove(&self, item: &WamItem) -> SparseMerkleProof {
        self.tree.prove(wam_leaf_key(item))
    }

    /// Applies one EIP-8289 item transition, adding before deleting.
    pub fn apply_item_transition(&mut self, add: &WamItems, del: Option<&WamItems>) {
        for item in add {
            self.wam.add_items(core::iter::once(item));
            self.update_item(item);
        }
        if let Some(del) = del {
            for item in del {
                self.wam.remove_items(core::iter::once(item));
                self.update_item(item);
            }
        }
    }

    /// Applies one EIP-8289 transition directly from block access lists.
    pub fn apply_bal_transition(&mut self, add: &BlockAccessList, del: Option<&BlockAccessList>) {
        let add = WamItems::from_bal(add);
        let del = del.map(WamItems::from_bal);
        self.apply_item_transition(&add, del.as_ref());
    }

    fn update_item(&mut self, item: &WamItem) {
        self.tree.update(wam_leaf_key(item), wam_leaf_value(self.wam.count(item)));
    }
}

/// Computes `SHA256(serialize(item))` using EIP-8289's canonical tagged serialization.
///
/// Accounts serialize as `0x00 || address`; slots serialize as
/// `0x01 || address || uint256_be(storage_key)`.
pub fn wam_leaf_key(item: &WamItem) -> B256 {
    let mut hasher = Sha256::new();
    match item {
        WamItem::Account(address) => {
            hasher.update([ACCOUNT_ITEM_TAG]);
            hasher.update(address.as_slice());
        }
        WamItem::Slot { address, key } => {
            hasher.update([SLOT_ITEM_TAG]);
            hasher.update(address.as_slice());
            hasher.update(key.to_be_bytes::<32>());
        }
    }
    B256::from_slice(&hasher.finalize())
}

/// Encodes a WAM counter as a generic SMT leaf value.
pub fn wam_leaf_value(count: u32) -> B256 {
    let mut value = [0u8; 32];
    value[28..].copy_from_slice(&count.to_be_bytes());
    B256::from(value)
}

/// Decodes a WAM counter from a generic SMT leaf value.
pub fn wam_counter(value: B256) -> u32 {
    u32::from_be_bytes(value.0[28..].try_into().expect("four-byte counter"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256, b256};

    fn account(byte: u8) -> WamItem {
        WamItem::account(Address::from([byte; 20]))
    }

    #[test]
    fn item_serialization_is_domain_separated() {
        let address = Address::from([0x11; 20]);
        let account = WamItem::account(address);
        let slot = WamItem::slot(address, U256::ZERO);

        assert_ne!(wam_leaf_key(&account), wam_leaf_key(&slot));
        assert_eq!(
            wam_leaf_key(&account),
            b256!("d16c677b92639584f9334f0d9e0ca0c51d1c18dc18ac8a0db62552c24c13f470")
        );
    }

    #[test]
    fn counter_encoding_round_trips() {
        assert_eq!(wam_counter(wam_leaf_value(42)), 42);
        assert_eq!(wam_leaf_value(0), B256::ZERO);
    }

    #[test]
    fn committed_transition_keeps_tree_and_multiset_in_sync() {
        let shared = account(0x66);
        let leaving = account(0x77);
        let first = WamItems::new(vec![shared, leaving]);
        let second = WamItems::new(vec![shared]);
        let mut state = CommittedWarmAccessMultiset::new();

        state.apply_item_transition(&first, None);
        state.apply_item_transition(&second, Some(&first));

        assert_eq!(state.wam().count(&shared), 1);
        assert_eq!(wam_counter(state.tree().value(wam_leaf_key(&shared))), 1);
        assert_eq!(state.wam().count(&leaving), 0);
        assert_eq!(state.tree().value(wam_leaf_key(&leaving)), B256::ZERO);
        assert!(state.prove(&shared).verify(
            wam_leaf_key(&shared),
            wam_leaf_value(1),
            state.root()
        ));
        assert_eq!(state.root(), CommittedWarmAccessMultiset::from_wam(state.wam.clone()).root());
    }
}
