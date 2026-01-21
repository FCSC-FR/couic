use std::collections::HashSet;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use tracing::{error, info, warn};

use client::{ApiVersion, CouicClient, CouicError, RemoteConfig};

use crate::config::Config;

use common::{Action, Entry, PeerJob, RawEntry, Tag};

const PEERING_INTERVAL: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_BUFFER_SIZE: usize = 1 << 14; // Max number of pending jobs

#[derive(Debug, thiserror::Error)]
pub enum PeerServiceError {
    #[error("Couic error: {0}")]
    Couic(#[from] CouicError),
    #[error("Configuration error: {0}")]
    Config(String),
}

pub struct PeerService {
    sender: Sender<PeerJob>,
}

impl PeerService {
    pub fn new(config: &Config) -> Result<Self, PeerServiceError> {
        let (sender, receiver) = bounded::<PeerJob>(MAX_BUFFER_SIZE);
        let clients = Self::initialize_clients(config)?;
        Self::spawn_worker(clients, receiver);
        Ok(Self { sender })
    }

    /// Queue a new peering job
    pub fn queue_job(&self, entry: &Entry, action: Action) {
        let tag = entry.tag.as_ref().and_then(|t| {
            if entry.in_set() {
                None
            } else {
                Tag::try_from(t.as_str()).ok()
            }
        });

        let job = PeerJob {
            action,
            entry: RawEntry {
                cidr: entry.cidr,
                tag,
                expiration: entry.expiration,
                metadata: None,
            },
        };

        if let Err(err) = self.sender.try_send(job) {
            match err {
                TrySendError::Full(_) => warn!(
                    "Peer job queue full (>{MAX_BUFFER_SIZE} pending). Dropping job to prevent memory exhaustion."
                ),
                TrySendError::Disconnected(_) => error!("Peer job channel disconnected."),
            }
        }
    }

    fn initialize_clients(config: &Config) -> Result<Vec<CouicClient>, PeerServiceError> {
        if let Some(peering) = &config.peering {
            peering
                .peers
                .iter()
                .map(|peer| {
                    let rc = RemoteConfig {
                        host: peer.host.clone(),
                        token: peer.token,
                        port: peer.port,
                        tls: peer.tls,
                    };
                    CouicClient::builder()
                        .version(ApiVersion::V1)
                        .build_remote(&rc)
                        .map_err(PeerServiceError::Couic)
                })
                .collect()
        } else {
            Err(PeerServiceError::Config(
                "Missing peering configuration".into(),
            ))
        }
    }

    fn spawn_worker(mut clients: Vec<CouicClient>, receiver: Receiver<PeerJob>) {
        thread::spawn(move || {
            let mut buffer_set = HashSet::with_capacity(4096);
            let mut backoff_delay = Duration::from_secs(1);

            loop {
                // Wait for a new job, with timeout
                match receiver.recv_timeout(PEERING_INTERVAL) {
                    Ok(job) => {
                        buffer_set.insert(job);
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        // no job this interval
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        warn!("Peer job channel disconnected; worker exiting");
                        break;
                    }
                }

                // Drain any additional queued jobs
                buffer_set.extend(receiver.try_iter());
                let buffer: Vec<PeerJob> = buffer_set.drain().collect();

                if buffer.is_empty() {
                    continue;
                }

                let mut all_success = true;

                // Send all jobs to every configured client
                for client in &mut clients {
                    match client.peer().drop(&buffer) {
                        Ok(_) => info!(
                            "Peering sync successful with {} ({} jobs)",
                            client.info(),
                            buffer.len()
                        ),
                        Err(e) => {
                            error!("Failed to peer with {}: {e}", client.info());
                            all_success = false;
                        }
                    }
                }

                if buffer_set.capacity() > 4096 {
                    buffer_set.shrink_to(4096);
                }

                // Exponential backoff if any client failed
                if all_success {
                    // reset backoff after success
                    backoff_delay = Duration::from_secs(1);
                } else {
                    thread::sleep(backoff_delay);
                    backoff_delay = (backoff_delay * 2).min(MAX_BACKOFF);
                }
            }
        });
    }
}
