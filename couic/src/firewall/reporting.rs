use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use tracing::{error, info, warn};

use crate::config;
use common::Report;

const CLIENT_TIMEOUT: u64 = 2;
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
pub const MAX_BUFFER_SIZE: usize = 1 << 12; // 4096 pending reports max

#[derive(Debug, thiserror::Error)]
pub enum ReportingError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("HTTP status error: {status} - Body: {body}")]
    HttpStatus {
        status: reqwest::StatusCode,
        body: String,
    },
}

#[derive(Debug, Clone)]
pub struct ReportingClient {
    webhook: String,
    client: Client,
}

impl ReportingClient {
    fn new(config: config::Reporting) -> Result<Self, ReportingError> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            )),
        );

        let client = Client::builder()
            .timeout(Duration::from_secs(CLIENT_TIMEOUT))
            .default_headers(headers)
            .build()?;

        Ok(Self {
            webhook: config.webhook,
            client,
        })
    }

    fn send_reports(&self, reports: &[Report]) -> Result<(), ReportingError> {
        let json_data = serde_json::to_string(reports)?;
        let resp = self.client.post(&self.webhook).body(json_data).send()?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            Err(ReportingError::HttpStatus { status, body })
        }
    }
}

#[derive(Debug)]
pub struct ReportingService {
    sender: Sender<Report>,
}

impl ReportingService {
    pub fn new(config: config::Reporting) -> Result<Self, ReportingError> {
        let (sender, receiver) = bounded::<Report>(MAX_BUFFER_SIZE);
        let service = Self { sender };
        service.spawn_worker(config, receiver)?;
        Ok(service)
    }

    /// Adds a new report to be processed asynchronously
    pub fn add_report(&self, report: Report) {
        if let Err(err) = self.sender.try_send(report) {
            match err {
                TrySendError::Full(_) => warn!(
                    "Reporting channel full (>{MAX_BUFFER_SIZE} pending). \
                     Dropping new report to prevent memory exhaustion."
                ),
                TrySendError::Disconnected(_) => {
                    error!("Reporting channel disconnected; unable to send report");
                }
            }
        }
    }

    fn spawn_worker(
        &self,
        config: config::Reporting,
        receiver: Receiver<Report>,
    ) -> Result<(), ReportingError> {
        let reporting_client = ReportingClient::new(config)?;

        thread::spawn(move || {
            let mut buffer = Vec::with_capacity(4096);
            let mut backoff_delay = Duration::from_secs(1);

            loop {
                match receiver.recv_timeout(FLUSH_INTERVAL) {
                    Ok(report) => buffer.push(report),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        error!("Reporting channel disconnected; worker exiting");
                        break;
                    }
                }

                buffer.extend(receiver.try_iter());

                if buffer.is_empty() {
                    continue;
                }

                match reporting_client.send_reports(&buffer) {
                    Ok(()) => {
                        info!(
                            "Sent {} reports successfully to {}",
                            buffer.len(),
                            reporting_client.webhook
                        );
                        buffer.clear();
                        if buffer.capacity() > 4096 {
                            buffer.shrink_to(4096);
                        }
                        backoff_delay = Duration::from_secs(1);
                    }
                    Err(err) => {
                        error!("Failed to send reports: {err}");
                        thread::sleep(backoff_delay);
                        backoff_delay = (backoff_delay * 2).min(MAX_BACKOFF);
                    }
                }
            }
        });

        Ok(())
    }
}
