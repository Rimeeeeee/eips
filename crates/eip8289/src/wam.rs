//! Warm-access multiset types and transition helpers.

use alloc::vec::Vec;
use alloy_eip7928::{AccountChanges, BlockAccessList};
use alloy_primitives::{
    Address, U256,
    map::{DefaultHashBuilder, HashMap, HashSet},
};
use core::iter::FusedIterator;

/// Number of historical blocks in the EIP-8289 warming window.
pub const WARMING_WINDOW: u64 = 256;

/// An item tracked by the warm-access multiset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum WamItem {
    /// An account address.
    Account(Address),
    /// A storage slot under an account address.
    Slot {
        /// Account address.
        address: Address,
        /// Storage key.
        key: U256,
    },
}

impl WamItem {
    /// Creates an account item.
    #[inline]
    pub const fn account(address: Address) -> Self {
        Self::Account(address)
    }

    /// Creates a storage-slot item.
    #[inline]
    pub const fn slot(address: Address, key: U256) -> Self {
        Self::Slot { address, key }
    }
}

/// Deduplicated WAM items extracted from one block access list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct WamItems {
    items: Vec<WamItem>,
}

impl WamItems {
    /// Creates a new item set from already deduplicated items.
    #[inline]
    pub const fn new(items: Vec<WamItem>) -> Self {
        Self { items }
    }

    /// Extracts the deduplicated EIP-8289 item set from a block access list.
    pub fn from_bal(bal: &BlockAccessList) -> Self {
        Self::from_accounts(bal)
    }

    /// Extracts the deduplicated EIP-8289 item set from account changes.
    pub fn from_accounts(accounts: &[AccountChanges]) -> Self {
        let mut items = Vec::new();
        let mut seen = HashSet::default();

        for account in accounts {
            push_unique(&mut items, &mut seen, WamItem::Account(account.address));

            for changes in account.storage_changes() {
                push_unique(&mut items, &mut seen, WamItem::slot(account.address, changes.slot));
            }

            for slot in account.storage_reads() {
                push_unique(&mut items, &mut seen, WamItem::slot(account.address, *slot));
            }
        }

        Self { items }
    }

    /// Returns `true` if there are no items.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the number of deduplicated items.
    #[inline]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns all items as a slice.
    #[inline]
    pub const fn as_slice(&self) -> &[WamItem] {
        self.items.as_slice()
    }

    /// Returns an iterator over the items.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, WamItem> {
        self.items.iter()
    }

    /// Consumes this value and returns the inner vector.
    #[inline]
    pub fn into_inner(self) -> Vec<WamItem> {
        self.items
    }
}

impl From<Vec<WamItem>> for WamItems {
    #[inline]
    fn from(items: Vec<WamItem>) -> Self {
        Self::new(items)
    }
}

impl From<WamItems> for Vec<WamItem> {
    #[inline]
    fn from(items: WamItems) -> Self {
        items.items
    }
}

impl<'a> IntoIterator for &'a WamItems {
    type Item = &'a WamItem;
    type IntoIter = core::slice::Iter<'a, WamItem>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for WamItems {
    type Item = WamItem;
    type IntoIter = alloc::vec::IntoIter<WamItem>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl FromIterator<WamItem> for WamItems {
    fn from_iter<I: IntoIterator<Item = WamItem>>(iter: I) -> Self {
        let mut items = Vec::new();
        let mut seen = HashSet::default();

        for item in iter {
            push_unique(&mut items, &mut seen, item);
        }

        Self { items }
    }
}

/// A refcounted warm-access multiset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WarmAccessMultiset {
    counts: HashMap<WamItem, u32>,
}

impl WarmAccessMultiset {
    /// Creates an empty WAM.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty WAM with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { counts: HashMap::with_capacity_and_hasher(capacity, DefaultHashBuilder::default()) }
    }

    /// Returns `true` if there are no warm items.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Returns the number of distinct warm items.
    #[inline]
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Returns the refcount for an item.
    #[inline]
    pub fn count(&self, item: &WamItem) -> u32 {
        self.counts.get(item).copied().unwrap_or_default()
    }

    /// Returns `true` if the item is warm.
    #[inline]
    pub fn is_warm(&self, item: &WamItem) -> bool {
        self.count(item) > 0
    }

    /// Returns an iterator over all tracked items and their refcounts.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&WamItem, u32)> + FusedIterator + '_ {
        self.counts.iter().map(|(item, count)| (item, *count))
    }

    /// Adds one block's items to the WAM.
    pub fn add_items<'a>(&mut self, items: impl IntoIterator<Item = &'a WamItem>) {
        for item in items {
            let count = self.counts.entry(*item).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    /// Removes one leaving block's items from the WAM.
    pub fn remove_items<'a>(&mut self, items: impl IntoIterator<Item = &'a WamItem>) {
        for item in items {
            if let Some(count) = self.counts.get_mut(item) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.counts.remove(item);
                }
            }
        }
    }

    /// Applies one EIP-8289 transition.
    ///
    /// `add` corresponds to `items(BAL(B - 1))`, while `del` corresponds to
    /// `items(BAL(B - 1 - WARMING_WINDOW))`. The addition is applied before deletion as specified
    /// by the draft.
    pub fn apply_transition<'a>(
        &mut self,
        add: impl IntoIterator<Item = &'a WamItem>,
        del: impl IntoIterator<Item = &'a WamItem>,
    ) {
        self.add_items(add);
        self.remove_items(del);
    }

    /// Applies one EIP-8289 transition directly from BAL item sets.
    #[inline]
    pub fn apply_item_transition(&mut self, add: &WamItems, del: Option<&WamItems>) {
        self.add_items(add);
        if let Some(del) = del {
            self.remove_items(del);
        }
    }

    /// Applies one EIP-8289 transition directly from block access lists.
    pub fn apply_bal_transition(&mut self, add: &BlockAccessList, del: Option<&BlockAccessList>) {
        let add = WamItems::from_bal(add);
        let del = del.map(WamItems::from_bal);
        self.apply_item_transition(&add, del.as_ref());
    }
}

fn push_unique(items: &mut Vec<WamItem>, seen: &mut HashSet<WamItem>, item: WamItem) {
    if seen.insert(item) {
        items.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eip7928::{BlockAccessIndex, SlotChanges, StorageChange};

    fn address(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    #[test]
    fn wam_items_deduplicate_accounts_and_slots() {
        let address = address(0x11);
        let bal = vec![
            AccountChanges::new(address)
                .with_storage_read(U256::from(1))
                .with_storage_read(U256::from(1))
                .with_storage_change(SlotChanges::new(
                    U256::from(1),
                    vec![StorageChange::new(BlockAccessIndex::new(0), U256::from(7))],
                ))
                .with_storage_change(SlotChanges::new(
                    U256::from(2),
                    vec![StorageChange::new(BlockAccessIndex::new(1), U256::from(8))],
                )),
            AccountChanges::new(address),
        ];

        let items = WamItems::from_bal(&bal);

        assert_eq!(
            items.as_slice(),
            &[
                WamItem::account(address),
                WamItem::slot(address, U256::from(1)),
                WamItem::slot(address, U256::from(2)),
            ]
        );
    }

    #[test]
    fn wam_transition_adds_before_deleting_leaving_items() {
        let address = address(0x22);
        let item = WamItem::account(address);
        let add = WamItems::new(vec![item]);
        let del = WamItems::new(vec![item]);
        let mut wam = WarmAccessMultiset::new();

        wam.apply_item_transition(&add, None);
        wam.apply_item_transition(&add, Some(&del));

        assert!(wam.is_warm(&item));
        assert_eq!(wam.count(&item), 1);
    }

    #[test]
    fn wam_removes_items_when_count_reaches_zero() {
        let address = address(0x33);
        let item = WamItem::slot(address, U256::from(5));
        let items = WamItems::new(vec![item]);
        let mut wam = WarmAccessMultiset::new();

        wam.apply_item_transition(&items, None);
        wam.apply_item_transition(&WamItems::default(), Some(&items));

        assert!(!wam.is_warm(&item));
        assert_eq!(wam.count(&item), 0);
        assert!(wam.is_empty());
    }

    #[test]
    fn wam_bal_transition_extracts_items() {
        let address = address(0x44);
        let bal = vec![AccountChanges::new(address).with_storage_read(U256::from(9))];
        let mut wam = WarmAccessMultiset::new();

        wam.apply_bal_transition(&bal, None);

        assert!(wam.is_warm(&WamItem::account(address)));
        assert!(wam.is_warm(&WamItem::slot(address, U256::from(9))));
    }
}
