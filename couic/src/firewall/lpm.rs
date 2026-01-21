use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use aya::maps::{IterableMap, LpmTrie, MapData, lpm_trie::Key};
use crossbeam_channel::Sender;
use tracing::{debug, error, info};

use super::tag::TagId;
use crate::error::CompositeError;
use common::{ErrorCode, NormalizedCidr};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const SHRINK_INTERVAL_CYCLES: u32 = 3600; // Shrink every hour

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StoredEntry {
    pub creation: u64,
    pub tag_id: u64,
    pub expiration: u64,
}

impl StoredEntry {
    pub fn expired(&self, now: u64) -> bool {
        if self.expiration == 0 {
            return false;
        }
        self.expiration <= now
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LpmStoreError {
    #[error("Error getting map info: {0}")]
    MapInfoError(String),
}

pub(crate) enum LpmMap {
    V4(LpmTrie<MapData, u32, u64>),
    V6(LpmTrie<MapData, u128, u64>),
}

impl LpmMap {
    fn insert_entry(
        &mut self,
        cidr: &NormalizedCidr,
        entry: &StoredEntry,
    ) -> Result<(), CompositeError> {
        match self {
            LpmMap::V4(map) => {
                let (prefix_len, addr) = cidr.to_lpm_key_v4().ok_or_else(|| {
                    CompositeError::new(ErrorCode::Einvalid, "Expected IPv4 address")
                })?;
                let key = Key::new(prefix_len, addr);
                map.insert(&key, entry.tag_id, 0)
            }
            LpmMap::V6(map) => {
                let (prefix_len, addr) = cidr.to_lpm_key_v6().ok_or_else(|| {
                    CompositeError::new(ErrorCode::Einvalid, "Expected IPv6 address")
                })?;
                let key = Key::new(prefix_len, addr);
                map.insert(&key, entry.tag_id, 0)
            }
        }
        .map_err(|e| CompositeError::new(ErrorCode::Einternal, &format!("ebpf insert error: {e}")))
    }

    fn remove_entry(&mut self, cidr: &NormalizedCidr) -> Result<(), CompositeError> {
        match self {
            LpmMap::V4(map) => {
                let (prefix_len, addr) = cidr.to_lpm_key_v4().ok_or_else(|| {
                    CompositeError::new(ErrorCode::Einvalid, "Expected IPv4 address")
                })?;
                let key = Key::new(prefix_len, addr);
                map.remove(&key)
            }
            LpmMap::V6(map) => {
                let (prefix_len, addr) = cidr.to_lpm_key_v6().ok_or_else(|| {
                    CompositeError::new(ErrorCode::Einvalid, "Expected IPv6 address")
                })?;
                let key = Key::new(prefix_len, addr);
                map.remove(&key)
            }
        }
        .map_err(|e| CompositeError::new(ErrorCode::Einternal, &format!("ebpf delete error: {e}")))
    }
}

pub struct LpmStore {
    ebpf_map: Arc<RwLock<LpmMap>>,
    max_entries: usize,
    items: Arc<RwLock<HashMap<NormalizedCidr, StoredEntry>>>,
    tag_release_sender: Sender<TagId>,
}

impl LpmStore {
    pub fn new(ebpf_map: LpmMap, tag_release_sender: Sender<TagId>) -> Result<Self, LpmStoreError> {
        // Get max entries from map info
        let max_entries = match &ebpf_map {
            LpmMap::V4(map) => match map.map().info() {
                Ok(info) => info.max_entries() as usize,
                Err(e) => return Err(LpmStoreError::MapInfoError(e.to_string())),
            },
            LpmMap::V6(map) => match map.map().info() {
                Ok(info) => info.max_entries() as usize,
                Err(e) => return Err(LpmStoreError::MapInfoError(e.to_string())),
            },
        };

        let store = Self {
            ebpf_map: Arc::new(RwLock::new(ebpf_map)),
            max_entries,
            items: Arc::new(RwLock::new(HashMap::new())),
            tag_release_sender,
        };

        store.launch_cleanup_thread();

        Ok(store)
    }

    pub fn add_stored(
        &self,
        cidr: NormalizedCidr,
        stored_entry: StoredEntry,
    ) -> Result<(), CompositeError> {
        let mut items = self
            .items
            .write()
            .map_err(|_| CompositeError::new(ErrorCode::Einternal, "Failed to acquire lock"))?;

        if items.len() >= self.max_entries {
            return Err(CompositeError::new(
                ErrorCode::Econflict,
                &format!(
                    "couic underlying ebpf map is full: max {} entries",
                    self.max_entries
                ),
            ));
        }

        match items.entry(cidr) {
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                let mut ebpf_map = self.ebpf_map.write().map_err(|_| {
                    CompositeError::new(ErrorCode::Einternal, "Failed to acquire ebpf_map lock")
                })?;

                ebpf_map.insert_entry(&cidr, &stored_entry).map_err(|e| {
                    if e.to_string().contains("mismatch") {
                        CompositeError::new(ErrorCode::Einvalid, &e.to_string())
                    } else {
                        CompositeError::new(
                            ErrorCode::Einternal,
                            &format!("unexpected error occurs while inserting ebpf entry: {e}"),
                        )
                    }
                })?;

                vacant_entry.insert(stored_entry);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                let mut ce =
                    CompositeError::new(ErrorCode::Econflict, "submitted entry is not valid");
                ce.add_detail(
                    "cidr",
                    ErrorCode::Econflict,
                    &format!("{cidr} already exists"),
                );
                Err(ce)
            }
        }
    }

    pub fn get_stored(&self, cidr: NormalizedCidr) -> Result<StoredEntry, CompositeError> {
        let items = self
            .items
            .read()
            .map_err(|_| CompositeError::new(ErrorCode::Einternal, "Failed to acquire lock"))?;

        items.get(&cidr).copied().ok_or_else(|| {
            let mut ce = CompositeError::new(ErrorCode::Enotfound, "submitted entry not found");
            ce.add_detail(
                "cidr",
                ErrorCode::Enotfound,
                &format!("cidr `{cidr}` not found"),
            );
            ce
        })
    }

    pub(crate) fn update_stored(
        &self,
        cidr: NormalizedCidr,
        new_stored: StoredEntry,
    ) -> Result<StoredEntry, CompositeError> {
        let mut items = self
            .items
            .write()
            .map_err(|_| CompositeError::new(ErrorCode::Einternal, "Failed to acquire lock"))?;

        if let Some(existing) = items.get_mut(&cidr) {
            let old_stored = *existing;

            // Update eBPF map if tag changed
            if existing.tag_id != new_stored.tag_id {
                let mut ebpf_map = self.ebpf_map.write().map_err(|_| {
                    CompositeError::new(ErrorCode::Einternal, "Failed to acquire ebpf_map lock")
                })?;

                ebpf_map.insert_entry(&cidr, &new_stored).map_err(|e| {
                    CompositeError::new(ErrorCode::Einternal, &format!("ebpf update error: {e}"))
                })?;
            }

            *existing = new_stored;
            Ok(old_stored)
        } else {
            let mut ce = CompositeError::new(ErrorCode::Enotfound, "submitted entry not found");
            ce.add_detail(
                "cidr",
                ErrorCode::Enotfound,
                &format!("cidr `{cidr}` not found"),
            );
            Err(ce)
        }
    }

    pub(crate) fn add_or_update_stored(
        &self,
        cidr: NormalizedCidr,
        new_stored: StoredEntry,
    ) -> Result<Option<StoredEntry>, CompositeError> {
        let mut items = self
            .items
            .write()
            .map_err(|_| CompositeError::new(ErrorCode::Einternal, "Failed to acquire lock"))?;

        if items.len() >= self.max_entries && !items.contains_key(&cidr) {
            return Err(CompositeError::new(
                ErrorCode::Econflict,
                &format!(
                    "couic underlying ebpf map is full: max {} entries",
                    self.max_entries
                ),
            ));
        }

        match items.entry(cidr) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let old_stored = *e.get();

                // Update eBPF map if tag changed
                if old_stored.tag_id != new_stored.tag_id {
                    let mut ebpf_map = self.ebpf_map.write().map_err(|_| {
                        CompositeError::new(ErrorCode::Einternal, "Failed to acquire ebpf_map lock")
                    })?;

                    ebpf_map.insert_entry(&cidr, &new_stored).map_err(|e| {
                        CompositeError::new(
                            ErrorCode::Einternal,
                            &format!("ebpf update error: {e}"),
                        )
                    })?;
                }

                e.insert(new_stored);
                Ok(Some(old_stored))
            }
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                let mut ebpf_map = self.ebpf_map.write().map_err(|_| {
                    CompositeError::new(ErrorCode::Einternal, "Failed to acquire ebpf_map lock")
                })?;

                ebpf_map.insert_entry(&cidr, &new_stored).map_err(|e| {
                    if e.to_string().contains("mismatch") {
                        CompositeError::new(ErrorCode::Einvalid, &e.to_string())
                    } else {
                        CompositeError::new(
                            ErrorCode::Einternal,
                            &format!("unexpected error occurs while inserting ebpf entry: {e}"),
                        )
                    }
                })?;

                debug!("Adding entry: {cidr:?}");
                vacant_entry.insert(new_stored);
                Ok(None)
            }
        }
    }

    pub fn list_stored(&self) -> Result<Vec<(NormalizedCidr, StoredEntry)>, CompositeError> {
        let items = self
            .items
            .read()
            .map_err(|_| CompositeError::new(ErrorCode::Einternal, "Failed to acquire lock"))?;

        Ok(items
            .iter()
            .map(|(cidr, stored)| (*cidr, *stored))
            .collect())
    }

    pub fn remove_stored(&self, cidr: NormalizedCidr) -> Result<StoredEntry, CompositeError> {
        let mut items = self
            .items
            .write()
            .map_err(|_| CompositeError::new(ErrorCode::Einternal, "Failed to acquire lock"))?;

        if let std::collections::hash_map::Entry::Occupied(entry) = items.entry(cidr) {
            debug!("Removing entry: {cidr:?}");

            let mut ebpf_map = self.ebpf_map.write().map_err(|_| {
                CompositeError::new(ErrorCode::Einternal, "Failed to acquire ebpf_map lock")
            })?;

            ebpf_map.remove_entry(&cidr).map_err(|e| {
                if e.to_string().contains("mismatch") {
                    CompositeError::new(ErrorCode::Einvalid, &e.to_string())
                } else {
                    CompositeError::new(
                        ErrorCode::Einternal,
                        &format!("unexpected error occurs while deleting ebpf entry: {e}"),
                    )
                }
            })?;

            Ok(entry.remove())
        } else {
            let mut ce = CompositeError::new(ErrorCode::Enotfound, "submitted entry not found");
            ce.add_detail(
                "cidr",
                ErrorCode::Enotfound,
                &format!("cidr `{cidr}` not found"),
            );
            Err(ce)
        }
    }

    pub(crate) fn list_sets_stored(&self) -> Vec<(NormalizedCidr, StoredEntry)> {
        self.items
            .read()
            .map(|items| {
                items
                    .iter()
                    .map(|(cidr, stored)| (*cidr, *stored))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.items
            .read()
            .map(|items| items.len())
            .unwrap_or_default()
    }

    fn launch_cleanup_thread(&self) {
        let items_clone = self.items.clone();
        let ebpf_map_clone = self.ebpf_map.clone();
        let tag_release_sender = self.tag_release_sender.clone();

        thread::spawn(move || {
            let mut cycle_count: u32 = 0;

            loop {
                thread::sleep(CLEANUP_INTERVAL);
                cycle_count = cycle_count.wrapping_add(1);

                let Ok(mut items) = items_clone.write() else {
                    error!("cleanup error: Failed to acquire write lock");
                    continue;
                };

                // Shrink HashMap capacity periodically
                if cycle_count.is_multiple_of(SHRINK_INTERVAL_CYCLES) {
                    let len = items.len();
                    let capacity = items.capacity();
                    // HashMap uses ~87.5% load factor, so minimum capacity for len items is ceil(len * 8/7)
                    // Only shrink if current capacity is at least 2x larger than needed
                    let min_capacity_after_shrink = len.saturating_add(len / 7).max(3);
                    if capacity > min_capacity_after_shrink.saturating_mul(2) {
                        items.shrink_to_fit();
                        debug!(
                            "cleanup: shrunk HashMap capacity from {} to {}",
                            capacity,
                            items.capacity()
                        );
                    }
                }

                if items.is_empty() {
                    continue;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let Ok(mut ebpf_map) = ebpf_map_clone.write() else {
                    error!("cleanup error: Failed to acquire ebpf_map lock");
                    continue;
                };

                let mut removed_count = 0;
                items.retain(|cidr, entry| {
                    if !entry.expired(now) {
                        return true;
                    }

                    match ebpf_map.remove_entry(cidr) {
                        Ok(()) => {
                            // Send tag_id to release channel
                            if let Err(e) = tag_release_sender.send(entry.tag_id) {
                                error!("cleanup: Failed to send tag {} for release: {e}", entry.tag_id);
                            }
                            removed_count += 1;
                            false
                        }
                        Err(e) => {
                            if e.to_string().contains("mismatch") {
                                error!(
                                    "cleanup error: IP version mismatch with map type for {cidr:?}"
                                );
                            } else {
                                error!(
                                    "cleanup error: unexpected error while deleting ebpf entry {cidr:?}: {e}"
                                );
                            }
                            true
                        }
                    }
                });

                if removed_count > 0 {
                    info!("cleanup: removed {removed_count} expired entries");
                }
            }
        });
    }
}
