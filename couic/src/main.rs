#![allow(clippy::similar_names)]
use std::fs;
use std::path::Path;
use std::process;
use std::sync::OnceLock;

use clap::{Arg, Command};
use tokio::net::UnixListener;
use tracing::error;

use crate::config::Config;
use crate::firewall::service::FirewallService;
use api::rbac::RBACService;
use security::{SEC_SOCKET_PERM, SecurityService};

mod api;
mod config;
mod error;
mod extractors;
mod firewall;
mod security;

pub const NAME: &str = "Couic";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
static CONFIG: OnceLock<Config> = OnceLock::new();

fn main() {
    println!("Starting {NAME} version {VERSION}");

    // Setup CLI
    let matches = Command::new(NAME)
        .version(VERSION)
        .about("Couic firewall daemon")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .default_value("couic.toml"),
        )
        .get_matches();

    // Setup configuration
    let config_path = matches.get_one::<String>("config").unwrap();
    let cfg = CONFIG.get_or_init(|| {
        Config::new(config_path).unwrap_or_else(|e| {
            eprintln!("Error loading configuration: {e}");
            std::process::exit(1);
        })
    });

    // Initialize directories before logging
    cfg.init_working_dir().unwrap_or_else(|e| {
        eprintln!("Error initializing default directories: {e}");
        std::process::exit(1);
    });

    // Setup logging
    let _guard = cfg.init_logger().unwrap_or_else(|e| {
        eprintln!("Error initializing logging: {e}");
        std::process::exit(1);
    });

    if let Err(e) = SecurityService::check_required_capabilities() {
        error!("Required capabilities: {e}");
        process::exit(1);
    }

    let rbac = match RBACService::new(cfg.clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to instantiate RBAC service: {e}");
            process::exit(1);
        }
    };

    let firewall = match FirewallService::new(cfg.clone()) {
        Ok(service) => service,
        Err(e) => {
            error!("Failed to instantiate firewall service: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = SecurityService::drop_all_caps_nonewprivs() {
        error!("Drop all capabilities: {e}");
        process::exit(1);
    }

    let app = api::create_router(firewall, rbac);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(server(app, cfg.clone()));
    process::exit(1);
}

async fn server(app: axum::Router, cfg: config::Config) {
    if Path::new(&cfg.server.socket).exists() {
        fs::remove_file(&cfg.server.socket).expect("Fail to remove couic socket file");
    }
    let uds =
        UnixListener::bind(&cfg.server.socket).expect("Error creating unix socket domain listener");

    // Set group ownership to "couic"
    if let Err(e) = SecurityService::set_owner_group_perms(
        &cfg.server.socket,
        &cfg.user,
        &cfg.group,
        SEC_SOCKET_PERM,
    ) {
        eprintln!("Failed to set socket permissions: {e}");
    }

    axum::serve(uds, app).await.unwrap();
}
