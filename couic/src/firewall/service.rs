use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::IpNet;

use aya::{
    Ebpf, EbpfError, include_bytes_aligned,
    maps::{LpmTrie, MapData, MapError, PerCpuArray, PerCpuHashMap as LruHashMap},
    programs::{ProgramError, Xdp, XdpFlags},
};
use crossbeam_channel::{Receiver, Sender, unbounded};
use tracing::{debug, error, info, warn};

use super::lpm::{LpmMap, LpmStore, LpmStoreError, StoredEntry};
use super::peer::{PeerService, PeerServiceError};
use super::reporting::{ReportingError, ReportingService};
use super::tag::{TagId, TagRegistry};
use crate::config::{Config, OperationMode};
use crate::error::CompositeError;
use crate::security::{SEC_FILE_PERM, SecurityService};
use common::{
    Action, Entry, ErrorCode, Expiration, MAX_SET_FILE_SIZE, MAX_SET_NAME_LENGTH, Metadata,
    NormalizedCidr, PktStats, Policy, Report, SET_EXTENSION, Set, SetName, SetSummary, Stats,
    TagStats,
};

#[derive(Debug, thiserror::Error)]
pub enum FirewallServiceError {
    #[error("Load error: {0}")]
    Load(#[from] EbpfError),
    #[error("Attach error: {0}")]
    Attach(#[from] ProgramError),
    #[error("Trie error: {0}")]
    Trie(#[from] MapError),
    #[error("Store error: {0}")]
    Store(#[from] LpmStoreError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Composite error: {0}")]
    Composite(#[from] CompositeError),
    #[error("Peer error: {0}")]
    Peer(#[from] PeerServiceError),
    #[error("Reporting error: {0}")]
    Reporting(#[from] ReportingError),
    #[error("Program not found: {0}")]
    ProgramNotFound(String),
}

#[derive(Default)]
struct SetCounter {
    updated: usize,
    removed: usize,
    created: usize,
}

pub struct FirewallService {
    _ebpf: Ebpf,
    drop_v4: LpmStore,
    drop_v6: LpmStore,
    ignore_v4: LpmStore,
    ignore_v6: LpmStore,
    stats: PerCpuArray<MapData, PktStats>,
    drop_stats_per_tag: LruHashMap<MapData, u64, PktStats>,
    ignore_stats_per_tag: LruHashMap<MapData, u64, PktStats>,
    peer_service: Option<PeerService>,
    reporting_service: Option<ReportingService>,
    tag_registry: TagRegistry,
    #[allow(dead_code)]
    tag_release_sender: Sender<TagId>,
    config: Config,
}

impl FirewallService {
    pub fn new(config: Config) -> Result<Self, FirewallServiceError> {
        let peer_service = if let Some(peering) = &config.peering {
            if peering.enabled {
                Some(PeerService::new(&config.clone())?)
            } else {
                None
            }
        } else {
            None
        };
        let reporting_service = if let Some(reporting) = &config.reporting {
            if reporting.enabled {
                Some(ReportingService::new(reporting.clone())?)
            } else {
                None
            }
        } else {
            None
        };

        let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/couic")))?;

        let program: &mut Xdp = ebpf
            .program_mut("couic")
            .ok_or_else(|| FirewallServiceError::ProgramNotFound("couic".to_string()))?
            .try_into()?;
        program.load()?;

        let xdp_flags = match config.operation_mode {
            OperationMode::Generic => XdpFlags::SKB_MODE,
            OperationMode::Native => XdpFlags::DRV_MODE,
            OperationMode::Offloaded => XdpFlags::HW_MODE,
        };
        for iface in &config.ifaces {
            program.attach(iface, xdp_flags)?;
            info!(
                "XDP program attached to interface: {iface} (mode: {:?})",
                config.operation_mode
            );
        }

        let tag_registry = TagRegistry::new();
        let (tag_release_sender, tag_release_receiver) = unbounded::<TagId>();

        let drop_v4 = LpmTrie::try_from(ebpf.take_map("couic_ipv4_drop").ok_or_else(|| {
            FirewallServiceError::ProgramNotFound("couic_ipv4_drop".to_string())
        })?)?;
        let drop_v4 = LpmStore::new(LpmMap::V4(drop_v4), tag_release_sender.clone())?;
        let drop_v6 = LpmTrie::try_from(ebpf.take_map("couic_ipv6_drop").ok_or_else(|| {
            FirewallServiceError::ProgramNotFound("couic_ipv6_drop".to_string())
        })?)?;
        let drop_v6 = LpmStore::new(LpmMap::V6(drop_v6), tag_release_sender.clone())?;
        let ignore_v4 =
            LpmTrie::try_from(ebpf.take_map("couic_ipv4_ignore").ok_or_else(|| {
                FirewallServiceError::ProgramNotFound("couic_ipv4_ignore".to_string())
            })?)?;
        let ignore_v4 = LpmStore::new(LpmMap::V4(ignore_v4), tag_release_sender.clone())?;
        let ignore_v6 =
            LpmTrie::try_from(ebpf.take_map("couic_ipv6_ignore").ok_or_else(|| {
                FirewallServiceError::ProgramNotFound("couic_ipv6_ignore".to_string())
            })?)?;
        let ignore_v6 = LpmStore::new(LpmMap::V6(ignore_v6), tag_release_sender.clone())?;
        let stats =
            PerCpuArray::try_from(ebpf.take_map("couic_stats").ok_or_else(|| {
                FirewallServiceError::ProgramNotFound("couic_stats".to_string())
            })?)?;
        let drop_stats_per_tag =
            LruHashMap::try_from(ebpf.take_map("couic_drop_stats_per_tag").ok_or_else(|| {
                FirewallServiceError::ProgramNotFound("couic_drop_stats_per_tag".to_string())
            })?)?;
        let ignore_stats_per_tag =
            LruHashMap::try_from(ebpf.take_map("couic_ignore_stats_per_tag").ok_or_else(
                || FirewallServiceError::ProgramNotFound("couic_ignore_stats_per_tag".to_string()),
            )?)?;

        // Launch tag release worker thread
        Self::launch_tag_release_worker(tag_registry.clone(), tag_release_receiver);

        let service = Self {
            _ebpf: ebpf,
            drop_v4,
            drop_v6,
            ignore_v4,
            ignore_v6,
            stats,
            drop_stats_per_tag,
            ignore_stats_per_tag,
            peer_service,
            reporting_service,
            tag_registry,
            tag_release_sender,
            config,
        };

        // Reload sets at startup
        service.reload_sets()?;

        Ok(service)
    }

    /// Background thread that processes tag releases from the cleanup threads
    fn launch_tag_release_worker(tag_registry: TagRegistry, receiver: Receiver<TagId>) {
        thread::spawn(move || {
            loop {
                if let Ok(tag_id) = receiver.recv() {
                    // Release the first one
                    if let Err(e) = tag_registry.release(tag_id) {
                        error!("Failed to release tag {tag_id}: {e}");
                    }

                    // Batch drain any additional pending releases
                    for tag_id in receiver.try_iter() {
                        if let Err(e) = tag_registry.release(tag_id) {
                            error!("Failed to release tag {tag_id}: {e}");
                        }
                    }
                } else {
                    warn!("Tag release channel disconnected; worker exiting");
                    break;
                }
            }
        });
    }

    fn get_lpm_store(&self, policy: Policy, is_ipv4: bool) -> &LpmStore {
        match (policy, is_ipv4) {
            (Policy::Drop, true) => &self.drop_v4,
            (Policy::Drop, false) => &self.drop_v6,
            (Policy::Ignore, true) => &self.ignore_v4,
            (Policy::Ignore, false) => &self.ignore_v6,
        }
    }

    /// Convert Entry to `StoredEntry` by acquiring a tag from the registry
    fn entry_to_stored(&self, entry: &Entry) -> Result<StoredEntry, CompositeError> {
        let tag_str = entry.tag.as_deref().unwrap_or("");
        let tag_id = self.tag_registry.acquire(tag_str).map_err(|e| {
            CompositeError::new(ErrorCode::Einternal, &format!("Tag acquisition error: {e}"))
        })?;

        Ok(StoredEntry {
            creation: entry.creation,
            tag_id,
            expiration: entry.expiration.as_timestamp(),
        })
    }

    /// Convert `StoredEntry` to Entry by looking up the tag name from the registry
    fn stored_to_entry(
        &self,
        cidr: NormalizedCidr,
        stored: StoredEntry,
    ) -> Result<Entry, CompositeError> {
        let tag_name = self
            .tag_registry
            .get_tag(stored.tag_id)
            .map_err(|e| {
                CompositeError::new(ErrorCode::Einternal, &format!("Tag lookup error: {e}"))
            })?
            .map(|s| s.to_string());

        Ok(Entry {
            creation: stored.creation,
            cidr,
            tag: tag_name,
            expiration: Expiration::from_timestamp(stored.expiration),
        })
    }

    fn release_tag(&self, tag_id: TagId) {
        if let Err(e) = self.tag_registry.release(tag_id) {
            error!("Failed to release tag {tag_id}: {e}");
        }
    }

    /// Add a given entry to the specified policy list of the firewall.
    pub fn add_entry(
        &self,
        policy: Policy,
        entry: &Entry,
        metadata: Option<Metadata>,
        propagate: bool,
    ) -> Result<(), CompositeError> {
        let lpm_store = self.get_lpm_store(policy, entry.cidr.is_v4());

        // Convert Entry to StoredEntry
        let stored_entry = self.entry_to_stored(entry)?;

        // Add to LPM store
        if let Err(e) = lpm_store.add_stored(entry.cidr, stored_entry) {
            // Release tag on failure
            self.release_tag(stored_entry.tag_id);
            return Err(e);
        }

        if propagate {
            // Peer sync if enabled
            if let Some(peer_service) = &self.peer_service {
                peer_service.queue_job(entry, Action::Add);
            }

            // Reporting if enabled
            if let Some(reporting_service) = &self.reporting_service {
                let report = Report {
                    action: Action::Add,
                    policy,
                    entry: entry.clone(),
                    metadata,
                };
                reporting_service.add_report(report);
            }
        }

        Ok(())
    }

    /// Get a given CIDR from the specified policy list of the firewall.
    pub fn get_entry(&self, policy: Policy, cidr: NormalizedCidr) -> Result<Entry, CompositeError> {
        let lpm_store = self.get_lpm_store(policy, cidr.is_v4());

        let stored = lpm_store.get_stored(cidr)?;
        self.stored_to_entry(cidr, stored)
    }

    /// List all entries from the specified policy list of the firewall.
    pub fn list_entries(&self, policy: Policy) -> Result<Vec<Entry>, CompositeError> {
        let mut entries = Vec::new();

        // List from IPv4 store
        for (cidr, stored) in self.get_lpm_store(policy, true).list_stored()? {
            entries.push(self.stored_to_entry(cidr, stored)?);
        }

        // List from IPv6 store
        for (cidr, stored) in self.get_lpm_store(policy, false).list_stored()? {
            entries.push(self.stored_to_entry(cidr, stored)?);
        }

        Ok(entries)
    }

    /// Remove a given entry from the specified policy list of the firewall.
    pub fn remove_entry(
        &self,
        policy: Policy,
        cidr: NormalizedCidr,
        propagate: bool,
    ) -> Result<(), CompositeError> {
        let lpm_store = self.get_lpm_store(policy, cidr.is_v4());

        // Remove from LPM store
        let stored = lpm_store.remove_stored(cidr)?;

        // Convert to Stored Entry
        let removed_entry = self.stored_to_entry(cidr, stored)?;

        // Release tag
        self.release_tag(stored.tag_id);

        if propagate {
            // Peer sync if enabled
            if let Some(peer_service) = &self.peer_service {
                peer_service.queue_job(&removed_entry, Action::Remove);
            }

            // Reporting if enabled
            if let Some(reporting_service) = &self.reporting_service {
                let report = Report {
                    action: Action::Remove,
                    policy,
                    entry: removed_entry,
                    metadata: None, // No metadata on removal
                };
                reporting_service.add_report(report);
            }
        }

        Ok(())
    }

    pub fn get_stats(&self) -> Result<Stats, CompositeError> {
        const LABELS: [&str; 5] = [
            "XDP_ABORTED",
            "XDP_DROP",
            "XDP_PASS",
            "XDP_TX",
            "XDP_REDIRECT",
        ];

        let mut xdp_stats = HashMap::with_capacity(LABELS.len());

        for (i, vals) in self.stats.iter().enumerate() {
            let label = LABELS.get(i).copied().unwrap_or("UNKNOWN");

            match vals {
                Ok(vals) => {
                    let counter = vals.iter().fold(PktStats::default(), |mut acc, cpuvalue| {
                        acc.rx_packets = acc.rx_packets.saturating_add(cpuvalue.rx_packets);
                        acc.rx_bytes = acc.rx_bytes.saturating_add(cpuvalue.rx_bytes);
                        acc
                    });

                    if i >= LABELS.len() {
                        warn!("Unexpected stats index: {} (max: {})", i, LABELS.len() - 1);
                        xdp_stats.insert(format!("UNKNOWN_{i}"), counter);
                    } else {
                        xdp_stats.insert(label.to_string(), counter);
                    }
                }
                Err(e) => {
                    error!("Error reading stats for {label}: {e}");
                    xdp_stats.insert(label.to_string(), PktStats::default());
                    return Err(CompositeError::new(
                        ErrorCode::Einternal,
                        &format!("Error reading stats for {label}: {e}"),
                    ));
                }
            }
        }

        let stats = Stats {
            drop_cidr_count: self.drop_v4.count() + self.drop_v6.count(),
            ignore_cidr_count: self.ignore_v4.count() + self.ignore_v6.count(),
            xdp: xdp_stats,
        };

        Ok(stats)
    }

    fn get_stats_tags_from_map(
        &self,
        map: &LruHashMap<MapData, u64, PktStats>,
    ) -> Result<TagStats, CompositeError> {
        let mut tag_stats = HashMap::new();

        for item in map.iter() {
            match item {
                Ok((tag_id, per_cpu_stats)) => {
                    let total = per_cpu_stats.iter().fold(
                        PktStats {
                            rx_packets: 0,
                            rx_bytes: 0,
                        },
                        |mut acc, s| {
                            acc.rx_packets += s.rx_packets;
                            acc.rx_bytes += s.rx_bytes;
                            acc
                        },
                    );

                    match self.tag_registry.get_tag_display(tag_id) {
                        Ok(Some(tag_name)) => {
                            tag_stats.insert(tag_name, total);
                        }
                        Ok(None) => {
                            debug!("Tag ID {tag_id} not found in registry");
                        }
                        Err(e) => {
                            error!("Error getting tag name for ID {tag_id}: {e}");
                            return Err(CompositeError::new(
                                ErrorCode::Einternal,
                                &format!("Tag acquisition error: {e}"),
                            ));
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading tag stats: {e}");
                    return Err(CompositeError::new(
                        ErrorCode::Einternal,
                        &format!("Error reading tag stats: {e}"),
                    ));
                }
            }
        }

        Ok(TagStats { tags: tag_stats })
    }

    pub fn get_stats_tags(&self, policy: Policy) -> Result<TagStats, CompositeError> {
        let map = match policy {
            Policy::Drop => &self.drop_stats_per_tag,
            Policy::Ignore => &self.ignore_stats_per_tag,
        };
        self.get_stats_tags_from_map(map)
    }

    /// Reloads all sets from configuration directories
    pub fn reload_sets(&self) -> Result<(), CompositeError> {
        let sets_ignore_dir = Path::new(&self.config.working_dir)
            .join("sets")
            .join("ignore");
        let sets_drop_dir = Path::new(&self.config.working_dir)
            .join("sets")
            .join("drop");

        // Reload ignore sets first (to avoid lockout)
        for (sets_dir, policy) in [
            (sets_ignore_dir, Policy::Ignore),
            (sets_drop_dir, Policy::Drop),
        ] {
            let sets_dir_str = sets_dir.to_str().ok_or_else(|| {
                CompositeError::new(
                    ErrorCode::Einternal,
                    &format!("Failed to convert {} to string", sets_dir.display()),
                )
            })?;
            self.reload_sets_from_dir(sets_dir_str, policy)?;
        }

        Ok(())
    }

    /// Reloads sets from a specific directory for a given policy
    fn reload_sets_from_dir(&self, set_path: &str, policy: Policy) -> Result<(), CompositeError> {
        let set_names = self.sets_names_from_dir(set_path)?;

        let mut target_set_v4 = HashMap::new();
        let mut target_set_v6 = HashMap::new();

        for set_name in &set_names {
            self.entries_from_set(set_path, set_name, &mut target_set_v4, &mut target_set_v6)?;
        }

        let counter_v4 = self.update_lpm_store(policy, true, target_set_v4)?;
        let counter_v6 = self.update_lpm_store(policy, false, target_set_v6)?;

        info!(
            "sets reload: policy={}, updated={}, removed={}, created={}",
            policy,
            counter_v4.updated + counter_v6.updated,
            counter_v4.removed + counter_v6.removed,
            counter_v4.created + counter_v6.created
        );

        Ok(())
    }

    fn update_lpm_store(
        &self,
        policy: Policy,
        is_ipv4: bool,
        target_set: HashMap<NormalizedCidr, Entry>,
    ) -> Result<SetCounter, CompositeError> {
        let store = self.get_lpm_store(policy, is_ipv4);

        // Get all stored entries and filter to sets (tag ends with SET_EXTENSION)
        let mut stored_map: HashMap<NormalizedCidr, StoredEntry> = store
            .list_sets_stored()
            .into_iter()
            .filter(|(_, stored)| {
                // Check if tag ends with SET_EXTENSION
                self.tag_registry
                    .get_tag(stored.tag_id)
                    .ok()
                    .flatten()
                    .is_some_and(|tag| tag.ends_with(SET_EXTENSION))
            })
            .collect();

        let mut counter = SetCounter::default();

        // Process entries in target_set
        for (target_key, target_entry) in target_set {
            if let Some(existing_stored) = stored_map.get(&target_key) {
                // Entry exists - check if update needed
                let target_tag = target_entry.tag.as_deref().unwrap_or("");

                // Get existing tag name to compare
                let existing_tag = self
                    .tag_registry
                    .get_tag(existing_stored.tag_id)
                    .ok()
                    .flatten()
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                if target_tag != existing_tag
                    || target_entry.expiration.as_timestamp() != existing_stored.expiration
                {
                    // Need to update - acquire new tag and update
                    let new_stored = self.entry_to_stored(&target_entry)?;
                    match store.update_stored(target_key, new_stored) {
                        Ok(old_stored) => {
                            // Release old tag
                            self.release_tag(old_stored.tag_id);
                            counter.updated += 1;
                        }
                        Err(e) => {
                            // Release new tag on failure
                            self.release_tag(new_stored.tag_id);
                            return Err(e);
                        }
                    }
                }
                // Mark as processed
                stored_map.remove(&target_key);
            } else {
                // Entry doesn't exist - add it
                let new_stored = self.entry_to_stored(&target_entry)?;
                match store.add_or_update_stored(target_key, new_stored) {
                    Ok(old_opt) => {
                        // Release old tag if there was one
                        if let Some(old_stored) = old_opt {
                            self.release_tag(old_stored.tag_id);
                        }
                        counter.created += 1;
                    }
                    Err(e) => {
                        // Release new tag on failure
                        self.release_tag(new_stored.tag_id);
                        return Err(e);
                    }
                }
            }
        }

        // Remove entries that exist in stored but not in target
        for (key, stored) in stored_map {
            match store.remove_stored(key) {
                Ok(_) => {
                    // Release tag
                    self.release_tag(stored.tag_id);
                    counter.removed += 1;
                }
                Err(e) => {
                    error!("Failed to remove set entry {key}: {e}");
                }
            }
        }

        Ok(counter)
    }

    /// Gets set names from a directory
    fn sets_names_from_dir(&self, path: &str) -> Result<Vec<String>, CompositeError> {
        let entries = fs::read_dir(path).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to read directory {path}: {e}"),
            )
        })?;

        let mut result = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|e| {
                CompositeError::new(
                    ErrorCode::Einternal,
                    &format!("Failed to access directory entry: {e}"),
                )
            })?;

            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext == SET_EXTENSION.trim_start_matches('.'))
            {
                // Check permissions
                SecurityService::check_owner_group_perms(
                    &path,
                    &self.config.user,
                    &self.config.group,
                    SEC_FILE_PERM,
                )
                .map_err(|e| {
                    CompositeError::new(
                        ErrorCode::Einvalid,
                        &format!("Set file {} has wrong permissions: {e}", path.display()),
                    )
                })?;

                // Check file size
                let metadata = fs::metadata(&path).map_err(|e| {
                    CompositeError::new(
                        ErrorCode::Einternal,
                        &format!("Failed to get metadata for file {}: {}", path.display(), e),
                    )
                })?;
                if metadata.len() > MAX_SET_FILE_SIZE {
                    return Err(CompositeError::new(
                        ErrorCode::Einvalid,
                        &format!(
                            "File {} exceeds the maximum allowed size of 5 MB",
                            path.display()
                        ),
                    ));
                }
                if let Some(file_stem) = path.file_stem().and_then(|name| name.to_str()) {
                    if file_stem
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                        && file_stem.len() <= MAX_SET_NAME_LENGTH
                    {
                        // Push the full file name (with extension) for later use
                        if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
                            result.push(file_name.to_string());
                        }
                    } else {
                        return Err(CompositeError::new(
                            ErrorCode::Einvalid,
                            &format!(
                                "Invalid set name: {file_stem}. Set name must contain only valid characters (a-zA-Z0-9-_) and be <= {MAX_SET_NAME_LENGTH} characters long"
                            ),
                        ));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Reads entries from a set file
    fn entries_from_set(
        &self,
        path: &str,
        set_name: &str,
        v4: &mut HashMap<NormalizedCidr, Entry>,
        v6: &mut HashMap<NormalizedCidr, Entry>,
    ) -> Result<(), CompositeError> {
        let abs_path = Path::new(path).join(set_name);
        let file = fs::File::open(&abs_path).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to read file {path}: {e}"),
            )
        })?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|e| {
                CompositeError::new(
                    ErrorCode::Einvalid,
                    &format!("Failed to read file {path}: {e}"),
                )
            })?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let entry = self.entry_from_line(line, set_name, &abs_path.to_string_lossy())?;

            if entry.cidr.is_v4() {
                v4.insert(entry.cidr, entry);
            } else {
                v6.insert(entry.cidr, entry);
            }
        }

        Ok(())
    }

    /// Parses an entry from a line in a set file
    fn entry_from_line(
        &self,
        line: &str,
        set_name: &str,
        path: &str,
    ) -> Result<Entry, CompositeError> {
        match line.parse() {
            Ok(cidr) => Ok(Entry {
                creation: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                cidr,
                tag: Some(set_name.to_string()),
                expiration: Expiration::never(),
            }),
            Err(_) => Err(CompositeError::new(
                ErrorCode::Einvalid,
                format!("error parsing set: {path}. Offending line: {line}").as_str(),
            )),
        }
    }

    /// Gets the directory path for sets of a given policy
    fn get_sets_dir(&self, policy: Policy) -> Result<std::path::PathBuf, CompositeError> {
        let dir = Path::new(&self.config.working_dir)
            .join("sets")
            .join(policy.to_string());

        if !dir.exists() {
            return Err(CompositeError::new(
                ErrorCode::Einternal,
                &format!("Sets directory does not exist: {}", dir.display()),
            ));
        }

        Ok(dir)
    }

    /// Gets the full path for a specific set file
    fn get_set_path(
        &self,
        policy: Policy,
        name: &SetName,
    ) -> Result<std::path::PathBuf, CompositeError> {
        let sets_dir = self.get_sets_dir(policy)?;
        Ok(sets_dir.join(format!("{name}{SET_EXTENSION}")))
    }

    /// Writes entries to a set file atomically
    fn write_set_file(
        &self,
        path: &std::path::Path,
        entries: &[IpNet],
    ) -> Result<(), CompositeError> {
        let tmp_path = path.with_extension("couic.tmp");

        // Write content to temp file
        let content: String = entries
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&tmp_path, &content).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to write temp file: {e}"),
            )
        })?;

        // Set proper permissions
        SecurityService::set_owner_group_perms(
            &tmp_path,
            &self.config.user,
            &self.config.group,
            SEC_FILE_PERM,
        )
        .map_err(|e| {
            // Clean up temp file on failure
            let _ = fs::remove_file(&tmp_path);
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to set file permissions: {e}"),
            )
        })?;

        // Atomic rename
        fs::rename(&tmp_path, path).map_err(|e| {
            // Clean up temp file on failure
            let _ = fs::remove_file(&tmp_path);
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to rename temp file: {e}"),
            )
        })?;

        Ok(())
    }

    /// Lists all sets for a given policy
    pub fn list_sets(&self, policy: Policy) -> Result<Vec<SetSummary>, CompositeError> {
        let sets_dir = self.get_sets_dir(policy)?;
        let mut sets = Vec::new();

        for entry in fs::read_dir(&sets_dir).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to read sets directory: {e}"),
            )
        })? {
            let entry = entry.map_err(|e| {
                CompositeError::new(
                    ErrorCode::Einternal,
                    &format!("Failed to access directory entry: {e}"),
                )
            })?;

            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext == SET_EXTENSION.trim_start_matches('.'))
            {
                let metadata = fs::metadata(&path).map_err(|e| {
                    CompositeError::new(
                        ErrorCode::Einternal,
                        &format!("Failed to get file metadata: {e}"),
                    )
                })?;

                if let Some(name_str) = path.file_stem().and_then(|n| n.to_str()) {
                    // Only include valid set names
                    if let Ok(name) = SetName::try_from(name_str) {
                        // Count non-empty, non-comment lines
                        let content = fs::read_to_string(&path).unwrap_or_default();
                        let entry_count = content
                            .lines()
                            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                            .count();

                        sets.push(SetSummary {
                            name,
                            entry_count,
                            file_size: metadata.len(),
                        });
                    }
                }
            }
        }

        Ok(sets)
    }

    /// Gets a specific set by name
    pub fn get_set(&self, policy: Policy, name: &SetName) -> Result<Set, CompositeError> {
        let set_path = self.get_set_path(policy, name)?;

        if !set_path.exists() {
            return Err(CompositeError::new(
                ErrorCode::Enotfound,
                &format!("Set '{name}' not found for policy '{policy}'"),
            ));
        }

        // Check permissions
        SecurityService::check_owner_group_perms(
            &set_path,
            &self.config.user,
            &self.config.group,
            SEC_FILE_PERM,
        )
        .map_err(|e| {
            CompositeError::new(
                ErrorCode::Einvalid,
                &format!("Set file has wrong permissions: {e}"),
            )
        })?;

        let content = fs::read_to_string(&set_path).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to read set file: {e}"),
            )
        })?;

        let mut errors = CompositeError::new(ErrorCode::Einvalid, "Invalid set file");
        let mut entries = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.parse::<IpNet>() {
                Ok(cidr) => entries.push(cidr),
                Err(e) => {
                    errors.add_detail(
                        &format!("line {}", i + 1),
                        ErrorCode::Einvalid,
                        &e.to_string(),
                    );
                }
            }
        }

        if errors.has_errors() {
            return Err(errors);
        }

        Ok(Set {
            name: name.clone(),
            entries,
        })
    }

    /// Creates a new set
    pub fn create_set(
        &self,
        policy: Policy,
        name: &SetName,
        entries: &[IpNet],
    ) -> Result<Set, CompositeError> {
        let set_path = self.get_set_path(policy, name)?;

        // Check if set already exists
        if set_path.exists() {
            return Err(CompositeError::new(
                ErrorCode::Econflict,
                &format!("Set '{name}' already exists for policy '{policy}'"),
            ));
        }

        self.write_set_file(&set_path, entries)?;

        Ok(Set {
            name: name.clone(),
            entries: entries.to_vec(),
        })
    }

    /// Updates an existing set (replaces all entries)
    pub fn update_set(
        &self,
        policy: Policy,
        name: &SetName,
        entries: &[IpNet],
    ) -> Result<Set, CompositeError> {
        let set_path = self.get_set_path(policy, name)?;

        // Check if set exists
        if !set_path.exists() {
            return Err(CompositeError::new(
                ErrorCode::Enotfound,
                &format!("Set '{name}' not found for policy '{policy}'"),
            ));
        }

        self.write_set_file(&set_path, entries)?;

        Ok(Set {
            name: name.clone(),
            entries: entries.to_vec(),
        })
    }

    /// Deletes a set
    pub fn delete_set(&self, policy: Policy, name: &SetName) -> Result<(), CompositeError> {
        let set_path = self.get_set_path(policy, name)?;

        if !set_path.exists() {
            return Err(CompositeError::new(
                ErrorCode::Enotfound,
                &format!("Set '{name}' not found for policy '{policy}'"),
            ));
        }

        fs::remove_file(&set_path).map_err(|e| {
            CompositeError::new(
                ErrorCode::Einternal,
                &format!("Failed to delete set file: {e}"),
            )
        })?;

        Ok(())
    }
}
