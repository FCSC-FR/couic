use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt as tracing_fmt;
use tracing_subscriber::prelude::*;
use uuid::Uuid;

use crate::security::{SEC_DIR_PERM, SecurityService};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    #[default]
    Daily,
    Weekly,
    Never,
}

impl LogRotation {
    pub fn to_rotation(self) -> Rotation {
        match self {
            LogRotation::Daily => Rotation::DAILY,
            LogRotation::Weekly => Rotation::WEEKLY,
            LogRotation::Never => Rotation::NEVER,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
    #[default]
    Generic,
    Native,
    Offloaded,
}

fn default_max_log_files() -> usize {
    7
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub ifaces: Vec<String>,
    #[serde(default)]
    pub operation_mode: OperationMode,
    pub working_dir: String,
    pub user: String,
    pub group: String,
    pub logging: Logging,
    pub server: Server,
    pub reporting: Option<Reporting>,
    pub peering: Option<Peering>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Server {
    pub socket: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Logging {
    pub dir: String,
    #[serde(default)]
    pub rotation: LogRotation,
    #[serde(default = "default_max_log_files")]
    pub max_log_files: usize,
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for Logging {
    fn default() -> Self {
        Self {
            dir: "/tmp".to_string(),
            rotation: LogRotation::default(),
            max_log_files: default_max_log_files(),
            format: LogFormat::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Peering {
    pub enabled: bool,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Peer {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub token: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reporting {
    pub enabled: bool,
    pub webhook: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Security error: {0}")]
    Security(#[from] crate::security::SecurityError),
    #[error("Failed to setup logging: {0}")]
    LoggingSetup(tracing_appender::rolling::InitError),
}

impl Config {
    pub fn new(path: &str) -> Result<Self, ConfigError> {
        let config_file = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&config_file)?;
        Ok(cfg)
    }

    pub fn init_working_dir(&self) -> Result<(), ConfigError> {
        let working_dir = Path::new(&self.working_dir);

        // Create main working directory
        if !working_dir.exists() {
            return Err(ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Working directory '{}' does not exist",
                    working_dir.display()
                ),
            )));
        }

        // Create subdirectories
        let subdirs = ["rbac", "sets", "rbac/clients", "sets/ignore", "sets/drop"];
        for subdir in subdirs {
            let dir_path = working_dir.join(subdir);
            if dir_path.exists() {
                // Verify permissions if it already exists
                SecurityService::check_owner_group_perms(
                    &dir_path,
                    &self.user,
                    &self.group,
                    SEC_DIR_PERM,
                )?;
            } else {
                fs::create_dir_all(&dir_path)?;
                SecurityService::set_owner_group_perms(
                    &dir_path,
                    &self.user,
                    &self.group,
                    SEC_DIR_PERM,
                )?;
            }
        }

        Ok(())
    }

    pub fn init_logger(&self) -> Result<(WorkerGuard, WorkerGuard), ConfigError> {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let (stdout_nb, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());

        let file_appender = Builder::new()
            .rotation(self.logging.rotation.to_rotation())
            .filename_prefix("couic")
            .filename_suffix("log")
            .max_log_files(self.logging.max_log_files)
            .build(&self.logging.dir)
            .map_err(ConfigError::LoggingSetup)?;
        let (file_nb, file_guard) = tracing_appender::non_blocking(file_appender);

        let registry = tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_fmt::layer().with_writer(stdout_nb));

        match self.logging.format {
            LogFormat::Text => {
                registry
                    .with(tracing_fmt::layer().with_writer(file_nb))
                    .init();
            }
            LogFormat::Json => {
                registry
                    .with(tracing_fmt::layer().json().with_writer(file_nb))
                    .init();
            }
        }

        Ok((stdout_guard, file_guard))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ifaces: vec!["lo".to_string()],
            operation_mode: OperationMode::default(),
            working_dir: "/tmp".to_string(),
            user: "test".to_string(),
            group: "test".to_string(),
            logging: Logging::default(),
            server: Server {
                socket: "/tmp/couic.sock".to_string(),
            },
            reporting: None,
            peering: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_serialization() {
        let config = Config::default();

        // Test serialization
        let toml_string = toml::to_string(&config).unwrap();
        assert!(toml_string.contains("ifaces = [\"lo\"]"));
        assert!(toml_string.contains("working_dir = \"/tmp\""));
        assert!(toml_string.contains("user = \"test\""));
        assert!(toml_string.contains("group = \"test\""));
        assert!(toml_string.contains("dir = \"/tmp\""));
        assert!(toml_string.contains("socket = \"/tmp/couic.sock\""));

        // Test deserialization
        let deserialized: Config = toml::from_str(&toml_string).unwrap();
        assert_eq!(config.ifaces, deserialized.ifaces);
        assert_eq!(config.working_dir, deserialized.working_dir);
        assert_eq!(config.user, deserialized.user);
        assert_eq!(config.group, deserialized.group);
        assert_eq!(config.logging.dir, deserialized.logging.dir);
        assert_eq!(config.server.socket, deserialized.server.socket);
        assert!(deserialized.reporting.is_none());
        assert!(deserialized.peering.is_none());
    }

    #[test]
    fn test_config_new_valid_file() {
        let mut temp_file = NamedTempFile::new().unwrap();

        let config_content = r#"
ifaces = ["eth0", "eth1"]
working_dir = "/var/lib/couic"
user = "couic"
group = "couic"

[logging]
dir = "/var/log/couic"

[server]
socket = "/var/run/couic.sock"
"#;

        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();

        assert_eq!(config.ifaces, vec!["eth0", "eth1"]);
        assert_eq!(config.working_dir, "/var/lib/couic");
        assert_eq!(config.user, "couic");
        assert_eq!(config.group, "couic");
        assert_eq!(config.logging.dir, "/var/log/couic");
        assert_eq!(config.server.socket, "/var/run/couic.sock");
        assert!(config.peering.is_none());
    }

    #[test]
    fn test_config_with_peering() {
        let mut temp_file = NamedTempFile::new().unwrap();

        let config_content = r#"
ifaces = ["eth0"]
working_dir = "/var/lib/couic"
user = "couic"
group = "couic"

[logging]
dir = "/var/log/couic"

[server]
socket = "/var/run/couic.sock"

[peering]
enabled = true

[[peering.peers]]
host = "peer1.example.com"
port = 8080
tls = true
token = "f018a987-c0ae-4269-a6e7-02a0fe77e553"

[[peering.peers]]
host = "peer2.example.com"
port = 8081
tls = false
token = "f657b53a-610e-4a5d-ae76-f1722d2854ac"
"#;

        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();

        assert!(config.peering.is_some());
        let peering = config.peering.unwrap();
        assert!(peering.enabled);
        assert_eq!(peering.peers.len(), 2);

        assert_eq!(peering.peers[0].host, "peer1.example.com");
        assert_eq!(peering.peers[0].port, 8080);
        assert!(peering.peers[0].tls);
        assert_eq!(
            peering.peers[0].token,
            uuid::Uuid::parse_str("f018a987-c0ae-4269-a6e7-02a0fe77e553").unwrap()
        );

        assert_eq!(peering.peers[1].host, "peer2.example.com");
        assert_eq!(peering.peers[1].port, 8081);
        assert!(!peering.peers[1].tls);
        assert_eq!(
            peering.peers[1].token,
            uuid::Uuid::parse_str("f657b53a-610e-4a5d-ae76-f1722d2854ac").unwrap()
        );
    }

    #[test]
    fn test_config_new_invalid_toml() {
        let mut temp_file = NamedTempFile::new().unwrap();

        let invalid_config = r#"
[logging
dir = "/var/log/couic"
invalid toml syntax
"#;

        temp_file.write_all(invalid_config.as_bytes()).unwrap();

        let result = Config::new(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Toml(_) => {
                // Expected TOML parsing error
            }
            _ => panic!("Expected TOML parsing error"),
        }
    }

    #[test]
    fn test_config_missing_required_fields() {
        let mut temp_file = NamedTempFile::new().unwrap();

        let incomplete_config = r#"
# Missing required fields like ifaces, working_dir, etc.
[logging]
dir = "/var/log/couic"
"#;

        temp_file.write_all(incomplete_config.as_bytes()).unwrap();

        let result = Config::new(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
        match result.unwrap_err() {
            ConfigError::Toml(_) => {
                // Expected because required fields are missing
            }
            _ => panic!("Expected TOML parsing error for missing fields"),
        }
    }

    #[test]
    fn test_config_with_empty_peering() {
        let mut temp_file = NamedTempFile::new().unwrap();

        let config_content = r#"
ifaces = ["eth0"]
working_dir = "/var/lib/couic"
user = "couic"
group = "couic"

[logging]
dir = "/var/log/couic"

[server]
socket = "/var/run/couic.sock"

[peering]
enabled = false
peers = []
"#;

        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();

        assert!(config.peering.is_some());
        let peering = config.peering.unwrap();
        assert!(!peering.enabled);
        assert!(peering.peers.is_empty());
    }

    #[test]
    fn test_comprehensive_config_roundtrip() {
        let original_config = Config {
            ifaces: vec!["eth0".to_string(), "eth1".to_string()],
            operation_mode: OperationMode::default(),
            working_dir: "/var/lib/couic".to_string(),
            user: "couic".to_string(),
            group: "couic".to_string(),
            logging: Logging {
                dir: "/var/log/couic".to_string(),
                ..Default::default()
            },
            server: Server {
                socket: "/var/run/couic.sock".to_string(),
            },
            peering: Some(Peering {
                enabled: true,
                peers: vec![Peer {
                    host: "peer1.example.com".to_string(),
                    port: 8080,
                    tls: true,
                    token: uuid::Uuid::parse_str("f657b53a-610e-4a5d-ae76-f1722d2854ac").unwrap(),
                }],
            }),
            reporting: Some(Reporting {
                enabled: true,
                webhook: "http://example.com/webhook".to_string(),
            }),
        };

        // Serialize to TOML
        let toml_string = toml::to_string(&original_config).unwrap();

        // Write to file and read back
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_string.as_bytes()).unwrap();

        let loaded_config = Config::new(temp_file.path().to_str().unwrap()).unwrap();

        // Verify all fields match
        assert_eq!(original_config.ifaces, loaded_config.ifaces);
        assert_eq!(original_config.working_dir, loaded_config.working_dir);
        assert_eq!(original_config.user, loaded_config.user);
        assert_eq!(original_config.group, loaded_config.group);
        assert_eq!(original_config.logging.dir, loaded_config.logging.dir);
        assert_eq!(original_config.server.socket, loaded_config.server.socket);

        assert!(loaded_config.peering.is_some());
        let loaded_peering = loaded_config.peering.unwrap();
        let original_peering = original_config.peering.unwrap();
        assert_eq!(original_peering.enabled, loaded_peering.enabled);
        assert_eq!(original_peering.peers.len(), loaded_peering.peers.len());
        assert_eq!(original_peering.peers[0].host, loaded_peering.peers[0].host);
        assert_eq!(original_peering.peers[0].port, loaded_peering.peers[0].port);
        assert_eq!(original_peering.peers[0].tls, loaded_peering.peers[0].tls);
        assert_eq!(
            original_peering.peers[0].token,
            loaded_peering.peers[0].token
        );
        assert!(loaded_config.reporting.is_some());
        let loaded_reporting = loaded_config.reporting.unwrap();
        let original_reporting = original_config.reporting.unwrap();
        assert_eq!(original_reporting.enabled, loaded_reporting.enabled);
        assert_eq!(original_reporting.webhook, loaded_reporting.webhook);
    }

    #[test]
    fn test_log_rotation_default() {
        assert_eq!(LogRotation::default(), LogRotation::Daily);
    }

    #[test]
    fn test_log_format_default() {
        assert_eq!(LogFormat::default(), LogFormat::Text);
    }

    #[test]
    fn test_logging_defaults() {
        let logging = Logging::default();
        assert_eq!(logging.dir, "/tmp");
        assert_eq!(logging.rotation, LogRotation::Daily);
        assert_eq!(logging.max_log_files, 7);
        assert_eq!(logging.format, LogFormat::Text);
    }

    #[test]
    fn test_log_rotation_to_rotation() {
        let _ = LogRotation::Daily.to_rotation();
        let _ = LogRotation::Weekly.to_rotation();
        let _ = LogRotation::Never.to_rotation();
    }

    #[test]
    fn test_config_backward_compatibility() {
        // Existing config format without new logging fields should still work
        let config_content = r#"
ifaces = ["eth0"]
working_dir = "/var/lib/couic"
user = "couic"
group = "couic"

[logging]
dir = "/var/log/couic"

[server]
socket = "/var/run/couic.sock"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();

        // Verify defaults are applied for new fields
        assert_eq!(config.logging.dir, "/var/log/couic");
        assert_eq!(config.logging.rotation, LogRotation::Daily);
        assert_eq!(config.logging.max_log_files, 7);
        assert_eq!(config.logging.format, LogFormat::Text);
    }

    #[test]
    fn test_config_with_full_logging() {
        let config_content = r#"
ifaces = ["eth0"]
working_dir = "/var/lib/couic"
user = "couic"
group = "couic"

[logging]
dir = "/var/log/couic"
rotation = "weekly"
max_log_files = 24
format = "text"

[server]
socket = "/var/run/couic.sock"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();

        assert_eq!(config.logging.dir, "/var/log/couic");
        assert_eq!(config.logging.rotation, LogRotation::Weekly);
        assert_eq!(config.logging.max_log_files, 24);
        assert_eq!(config.logging.format, LogFormat::Text);
    }

    #[test]
    fn test_logging_serialization_roundtrip() {
        let logging = Logging {
            dir: "/var/log/test".to_string(),
            rotation: LogRotation::Weekly,
            max_log_files: 10,
            format: LogFormat::Text,
        };

        let toml_string = toml::to_string(&logging).unwrap();
        let deserialized: Logging = toml::from_str(&toml_string).unwrap();

        assert_eq!(logging.dir, deserialized.dir);
        assert_eq!(logging.rotation, deserialized.rotation);
        assert_eq!(logging.max_log_files, deserialized.max_log_files);
        assert_eq!(logging.format, deserialized.format);
    }

    #[test]
    fn test_all_rotation_values() {
        for (toml_val, expected) in [
            ("daily", LogRotation::Daily),
            ("weekly", LogRotation::Weekly),
            ("never", LogRotation::Never),
        ] {
            let config_content = format!(
                r#"
ifaces = ["eth0"]
working_dir = "/tmp"
user = "test"
group = "test"

[logging]
dir = "/tmp"
rotation = "{}"

[server]
socket = "/tmp/couic.sock"
"#,
                toml_val
            );

            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(config_content.as_bytes()).unwrap();

            let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();
            assert_eq!(config.logging.rotation, expected);
        }
    }

    #[test]
    fn test_all_format_values() {
        for (toml_val, expected) in [("text", LogFormat::Text), ("json", LogFormat::Json)] {
            let config_content = format!(
                r#"
ifaces = ["eth0"]
working_dir = "/tmp"
user = "test"
group = "test"

[logging]
dir = "/tmp"
format = "{}"

[server]
socket = "/tmp/couic.sock"
"#,
                toml_val
            );

            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(config_content.as_bytes()).unwrap();

            let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();
            assert_eq!(config.logging.format, expected);
        }
    }

    #[test]
    fn test_operation_mode_default() {
        assert_eq!(OperationMode::default(), OperationMode::Generic);
    }

    #[test]
    fn test_all_operation_mode_values() {
        for (toml_val, expected) in [
            ("generic", OperationMode::Generic),
            ("native", OperationMode::Native),
            ("offloaded", OperationMode::Offloaded),
        ] {
            let config_content = format!(
                r#"
ifaces = ["eth0"]
operation_mode = "{}"
working_dir = "/tmp"
user = "test"
group = "test"

[logging]
dir = "/tmp"

[server]
socket = "/tmp/couic.sock"
"#,
                toml_val
            );

            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(config_content.as_bytes()).unwrap();

            let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();
            assert_eq!(config.operation_mode, expected);
        }
    }

    #[test]
    fn test_operation_mode_backward_compatibility() {
        // Config without operation_mode should default to Generic
        let config_content = r#"
ifaces = ["eth0"]
working_dir = "/tmp"
user = "test"
group = "test"

[logging]
dir = "/tmp"

[server]
socket = "/tmp/couic.sock"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = Config::new(temp_file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.operation_mode, OperationMode::Generic);
    }
}
