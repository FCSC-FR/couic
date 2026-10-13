use std::thread;
use std::time::{Duration, Instant};

use clap::Args;
use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL};

use client::CouicClient;
use common::{Policy, Stats, TagStats};

use super::{Command, CommandError};

const ANSI_CLEAR_SCREEN: &str = "\x1B[2J\x1B[1;1H";
const ANSI_HIGHLIGHT: &str = "\x1b[47;30m";
const ANSI_RESET: &str = "\x1b[0m";

#[derive(Args, Debug)]
pub struct StatsCommand {
    #[command(subcommand)]
    command: StatsSubCommand,
}

#[derive(clap::Subcommand, Debug)]
#[command(about = "Display statistics")]
enum StatsSubCommand {
    #[command(about = "Display global statistics")]
    Global {
        #[arg(short, long)]
        live: bool,
        #[arg(long, conflicts_with = "live")]
        json: bool,
    },
    #[command(about = "Display drop statistics per tag")]
    Drop {
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Display ignore statistics per tag")]
    Ignore {
        #[arg(long)]
        json: bool,
    },
}

impl Command for StatsCommand {
    fn execute(&self, client: &mut CouicClient) -> Result<(), CommandError> {
        match &self.command {
            StatsSubCommand::Global {
                live: false,
                json: true,
            } => {
                let stats = client.stats().get()?;
                println!("{}", serde_json::to_string_pretty(&stats)?);
            }
            StatsSubCommand::Global {
                live: false,
                json: false,
            } => {
                println!("{}", client.stats().get()?);
            }
            StatsSubCommand::Global { live: true, .. } => {
                let mut prev_stats: Option<Stats> = None;
                let mut prev_time = Instant::now();

                loop {
                    print!("{ANSI_CLEAR_SCREEN}");

                    let current_stats = client.stats().get()?;
                    let current_time = Instant::now();
                    let elapsed = current_time.duration_since(prev_time).as_secs_f64();

                    display_live_stats(&current_stats, prev_stats.as_ref(), elapsed);

                    prev_stats = Some(current_stats);
                    prev_time = current_time;

                    thread::sleep(Duration::from_secs(1));
                }
            }
            StatsSubCommand::Drop { json: true } => {
                let tag_stats = client.stats().tag(Policy::Drop)?;
                println!("{}", serde_json::to_string_pretty(&tag_stats)?);
            }
            StatsSubCommand::Drop { json: false } => {
                let tag_stats = client.stats().tag(Policy::Drop)?;
                print_tag_stats(&tag_stats, "drop");
            }
            StatsSubCommand::Ignore { json: true } => {
                let tag_stats = client.stats().tag(Policy::Ignore)?;
                println!("{}", serde_json::to_string_pretty(&tag_stats)?);
            }
            StatsSubCommand::Ignore { json: false } => {
                let tag_stats = client.stats().tag(Policy::Ignore)?;
                print_tag_stats(&tag_stats, "ignore");
            }
        }
        Ok(())
    }
}

#[allow(clippy::cast_precision_loss)]
fn display_live_stats(current_stats: &Stats, prev_stats: Option<&Stats>, elapsed: f64) {
    println!("Every {elapsed:.1}s: stats");
    println!("Drop CIDR Count: {}", current_stats.drop_cidr_count);
    println!("Ignore CIDR Count: {}", current_stats.ignore_cidr_count);
    println!("XDP Stats:");

    let mut actions: Vec<_> = current_stats.xdp.keys().collect();
    actions.sort();

    for action in actions {
        if let Some(current_stat) = current_stats.xdp.get(action) {
            println!("  Action: {action}");

            let prev_stat = prev_stats.and_then(|p| p.xdp.get(action));

            let (packets_rate, bytes_rate, highlight_packets, highlight_bytes) =
                prev_stat.map_or((0.0, 0.0, false, false), |prev| {
                    let packet_delta = current_stat.rx_packets.saturating_sub(prev.rx_packets);
                    let byte_delta = current_stat.rx_bytes.saturating_sub(prev.rx_bytes);
                    let pps = packet_delta as f64 / elapsed;
                    let bps = byte_delta as f64 / elapsed;
                    (
                        pps,
                        bps,
                        current_stat.rx_packets != prev.rx_packets,
                        current_stat.rx_bytes != prev.rx_bytes,
                    )
                });

            println!(
                "    RX Packets: {}",
                format_rate_highlight(packets_rate, "pps", highlight_packets)
            );
            println!(
                "    RX Bytes: {}",
                format_rate_highlight(bytes_rate, "bps", highlight_bytes)
            );
        }
    }
}

fn format_rate_highlight(value: f64, unit: &str, highlight: bool) -> String {
    let formatted_value = if value >= 1_000_000_000.0 {
        format!("{:.1}g{}", value / 1_000_000_000.0, unit)
    } else if value >= 1_000_000.0 {
        format!("{:.1}m{}", value / 1_000_000.0, unit)
    } else if value >= 1_000.0 {
        format!("{:.1}k{}", value / 1_000.0, unit)
    } else {
        format!("{value:.1} {unit}")
    };

    if highlight {
        format!("{ANSI_HIGHLIGHT}{formatted_value}{ANSI_RESET}")
    } else {
        formatted_value
    }
}

fn print_tag_stats(tag_stats: &TagStats, policy: &str) {
    if tag_stats.tags.is_empty() {
        println!("No tag statistics available.");
        return;
    }

    let mut table = Table::new();
    table
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Tag", "Policy", "RX Packets", "RX Bytes"]);

    let mut tag_names: Vec<_> = tag_stats.tags.keys().collect();
    tag_names.sort();

    for tag_name in tag_names {
        if let Some(stats) = tag_stats.tags.get(tag_name) {
            table.add_row(vec![
                Cell::new(tag_name),
                Cell::new(policy),
                Cell::new(stats.rx_packets),
                Cell::new(stats.rx_bytes),
            ]);
        }
    }

    println!("{table}");
}
