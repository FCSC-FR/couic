use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL};
use humantime::parse_duration;

use client::CouicClient;
use common::{Entry, Expiration, NormalizedCidr, Policy, RawEntry, Tag};

use super::{Command, CommandError};

const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_MINUTE: u64 = 60;

#[derive(Args, Debug)]
pub struct PolicyCommand<T: Subcommand> {
    #[command(subcommand)]
    command: T,
}

impl<T: Subcommand + PolicyAction> Command for PolicyCommand<T> {
    fn execute(&self, client: &mut CouicClient) -> Result<(), CommandError> {
        self.command.execute(client)
    }
}

trait PolicyAction {
    fn execute(&self, client: &mut CouicClient) -> Result<(), CommandError>;
}

fn calculate_expiration(expiration: &str) -> Result<u64, CommandError> {
    if expiration != "0" {
        let duration = parse_duration(expiration)
            .map_err(|_| CommandError::Generic("Invalid expiration format".to_string()))?;
        return SystemTime::now()
            .checked_add(duration)
            .ok_or_else(|| CommandError::Generic("Invalid expiration time".to_string()))?
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| CommandError::Generic(e.to_string()));
    }
    Ok(0)
}

fn format_expiration(expiration: Expiration) -> String {
    if expiration.is_never() {
        "never".to_string()
    } else {
        let now = SystemTime::now();
        let Some(expiration_time) =
            UNIX_EPOCH.checked_add(Duration::from_secs(expiration.as_timestamp()))
        else {
            return "invalid".to_string();
        };
        expiration_time.duration_since(now).map_or_else(
            |_| "expired".to_string(),
            |duration| {
                let total_seconds = duration.as_secs();
                let days = total_seconds.div_euclid(SECONDS_PER_DAY);
                let mut remainder = total_seconds.rem_euclid(SECONDS_PER_DAY);

                let hours = remainder.div_euclid(SECONDS_PER_HOUR);
                remainder = remainder.rem_euclid(SECONDS_PER_HOUR);

                let minutes = remainder.div_euclid(SECONDS_PER_MINUTE);
                let seconds = remainder.rem_euclid(SECONDS_PER_MINUTE);

                if days > 0 {
                    format!("{days}d {hours}h{minutes}m{seconds}s")
                } else if hours > 0 {
                    format!("{hours}h{minutes}m{seconds}s")
                } else if minutes > 0 {
                    format!("{minutes}m{seconds}s")
                } else {
                    format!("{seconds}s")
                }
            },
        )
    }
}

fn matches_tag(tag: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let starts_wild = pattern.starts_with('*');
        let ends_wild = pattern.ends_with('*');

        match (starts_wild, ends_wild) {
            (true, true) => {
                // *substring* or * or **
                if pattern.len() <= 2 {
                    // "*" or "**" matches everything
                    true
                } else {
                    pattern
                        .strip_prefix('*')
                        .and_then(|p| p.strip_suffix('*'))
                        .is_some_and(|inner| tag.contains(inner))
                }
            }
            (true, false) => {
                // *suffix
                pattern
                    .strip_prefix('*')
                    .is_some_and(|suffix| !suffix.is_empty() && tag.ends_with(suffix))
            }
            (false, true) => {
                // prefix*
                pattern
                    .strip_suffix('*')
                    .is_some_and(|prefix| !prefix.is_empty() && tag.starts_with(prefix))
            }
            (false, false) => {
                // exact match
                tag == pattern
            }
        }
    })
}

fn filter_entries(entries: Vec<Entry>, tags: Option<&str>) -> Vec<Entry> {
    let patterns: Vec<String> = tags
        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    if patterns.is_empty() {
        entries
    } else {
        entries
            .into_iter()
            .filter(|entry| {
                entry
                    .tag
                    .as_ref()
                    .is_some_and(|tag| matches_tag(tag, &patterns))
            })
            .collect()
    }
}

fn print_entries(entries: Vec<Entry>, quiet: bool, policy: &str) {
    if quiet {
        for entry in entries {
            println!("{}", entry.cidr);
        }
    } else {
        let mut table = Table::new();
        table
            .load_style(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["Policy", "CIDR", "Tag", "Expiration"]);

        for entry in entries {
            table.add_row(vec![
                Cell::new(policy),
                Cell::new(entry.cidr),
                Cell::new(entry.tag.unwrap_or_else(|| "-".to_string())),
                Cell::new(format_expiration(entry.expiration)),
            ]);
        }
        println!("{table}");
    }
}

fn print_entry(entry: Entry, policy: &str) {
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Policy", "CIDR", "Tag", "Expiration"]);

    table.add_row(vec![
        Cell::new(policy),
        Cell::new(entry.cidr),
        Cell::new(entry.tag.unwrap_or_else(|| "-".to_string())),
        Cell::new(format_expiration(entry.expiration)),
    ]);

    println!("{table}");
}

#[derive(Subcommand, Debug)]
#[command(about = "Control drop policy")]
pub enum DropSubCommand {
    #[command(about = "Add entry to drop list")]
    Add {
        #[arg(help = "CIDR block to add to the drop list, e.g., 192.168.0.0/24")]
        cidr: NormalizedCidr,
        #[arg(
            short,
            long,
            default_value = "couicctl",
            help = "Tag for the entry, e.g., my_tag",
            long_help = "Tag for the entry. Valid characters are a-zA-Z0-9-_ and max length is 64"
        )]
        tag: Option<Tag>,
        #[arg(
            short = 'e',
            long,
            default_value = "0",
            help = "Expiration time in minutes",
            long_help = "Expiration time in minutes. The default value is zero, which means the entry never expires; otherwise, the expiration is set in minutes in the future."
        )]
        expiration: String,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Remove entry from drop list")]
    Delete { cidr: NormalizedCidr },
    #[command(about = "List entries in drop list")]
    List {
        #[arg(short, long)]
        quiet: bool,
        #[arg(
            short = 't',
            long = "tags",
            help = "Filter entries by tags. Supports wildcards (*). Multiple tags can be specified, separated by commas. Quote wildcards to prevent shell expansion (e.g., -t '*')."
        )]
        tags: Option<String>,
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
    },
    #[command(about = "Inspect entry in drop list")]
    Inspect {
        cidr: NormalizedCidr,
        #[arg(long)]
        json: bool,
    },
}

impl PolicyAction for DropSubCommand {
    fn execute(&self, client: &mut CouicClient) -> Result<(), CommandError> {
        match self {
            Self::Add {
                cidr,
                tag,
                expiration,
                json,
            } => {
                let exp = calculate_expiration(expiration)?;
                let entry = RawEntry {
                    cidr: *cidr,
                    tag: tag.clone(),
                    expiration: Expiration::from_timestamp(exp),
                    metadata: None,
                };
                let entry = client.policy().add(Policy::Drop, &entry)?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&entry)?);
                } else {
                    print_entry(entry, "drop");
                }
            }
            Self::Delete { cidr } => {
                client.policy().delete(Policy::Drop, &cidr.to_string())?;
            }
            Self::Inspect { cidr, json } => {
                let entry = client.policy().get(Policy::Drop, &cidr.to_string())?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&entry)?);
                } else {
                    print_entry(entry, "drop");
                }
            }
            Self::List { quiet, tags, json } => {
                let entries = filter_entries(client.policy().list(Policy::Drop)?, tags.as_deref());
                if *json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    print_entries(entries, *quiet, "drop");
                }
            }
        }
        Ok(())
    }
}

#[derive(Subcommand, Debug)]
#[command(about = "Control ignore policy")]
pub enum IgnoreSubCommand {
    #[command(about = "Add entry to ignore list")]
    Add {
        #[arg(help = "CIDR block to add to the ignore list, e.g., 192.168.0.0/24")]
        cidr: NormalizedCidr,
        #[arg(
            short,
            long,
            help = "Tag for the entry, e.g., my_tag",
            long_help = "Tag for the entry. Valid characters are a-zA-Z0-9-_ and max length is 64"
        )]
        tag: Option<Tag>,
        #[arg(
            short = 'e',
            long,
            default_value = "0",
            help = "Expiration time in minutes",
            long_help = "Expiration time in minutes. The default value is zero, which means the entry never expires; otherwise, the expiration is set in minutes in the future."
        )]
        expiration: String,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Remove entry from ignore list")]
    Delete { cidr: NormalizedCidr },
    #[command(about = "List entries in ignore list")]
    List {
        #[arg(short, long)]
        quiet: bool,
        #[arg(
            short = 't',
            long = "tags",
            help = "Filter entries by tags. Supports wildcards (*). Multiple tags can be specified, separated by commas. Quote wildcards to prevent shell expansion (e.g., -t '*')."
        )]
        tags: Option<String>,
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
    },
    #[command(about = "Inspect entry in ignore list")]
    Inspect {
        cidr: NormalizedCidr,
        #[arg(long)]
        json: bool,
    },
}

impl PolicyAction for IgnoreSubCommand {
    fn execute(&self, client: &mut CouicClient) -> Result<(), CommandError> {
        match self {
            Self::Add {
                cidr,
                tag,
                expiration,
                json,
            } => {
                let exp = calculate_expiration(expiration)?;
                let entry = RawEntry {
                    cidr: *cidr,
                    tag: tag.clone(),
                    expiration: Expiration::from_timestamp(exp),
                    metadata: None,
                };
                let entry = client.policy().add(Policy::Ignore, &entry)?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&entry)?);
                } else {
                    print_entry(entry, "ignore");
                }
            }
            Self::Delete { cidr } => {
                client.policy().delete(Policy::Ignore, &cidr.to_string())?;
            }
            Self::Inspect { cidr, json } => {
                let entry = client.policy().get(Policy::Ignore, &cidr.to_string())?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&entry)?);
                } else {
                    print_entry(entry, "ignore");
                }
            }
            Self::List { quiet, tags, json } => {
                let entries =
                    filter_entries(client.policy().list(Policy::Ignore)?, tags.as_deref());
                if *json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    print_entries(entries, *quiet, "ignore");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_tag_exact_match() {
        assert!(matches_tag("fail2ban-sshd", &["fail2ban-sshd".to_string()]));
        assert!(!matches_tag("fail2ban-sshd", &["fail2ban".to_string()]));
        assert!(!matches_tag("fail2ban-sshd", &["sshd".to_string()]));
    }

    #[test]
    fn test_matches_tag_prefix_wildcard() {
        // Pattern: prefix*
        assert!(matches_tag("fail2ban-sshd", &["fail*".to_string()]));
        assert!(matches_tag("fail2ban-sshd", &["fail2ban*".to_string()]));
        assert!(matches_tag(
            "fail2ban-sshd",
            &["fail2ban-sshd*".to_string()]
        ));
        assert!(!matches_tag("fail2ban-sshd", &["ban*".to_string()]));
        assert!(!matches_tag("fail2ban-sshd", &["sshd*".to_string()]));
    }

    #[test]
    fn test_matches_tag_suffix_wildcard() {
        // Pattern: *suffix
        assert!(matches_tag("fail2ban-sshd", &["*sshd".to_string()]));
        assert!(matches_tag("fail2ban-sshd", &["*-sshd".to_string()]));
        assert!(matches_tag("fail2ban-sshd", &["*ban-sshd".to_string()]));
        assert!(!matches_tag("fail2ban-sshd", &["*fail".to_string()]));
        assert!(!matches_tag("fail2ban-sshd", &["*ail".to_string()]));
    }

    #[test]
    fn test_matches_tag_contains_wildcard() {
        // Pattern: *substring*
        assert!(matches_tag("fail2ban-sshd", &["*fail*".to_string()]));
        assert!(matches_tag("fail2ban-sshd", &["*2ban*".to_string()]));
        assert!(matches_tag("fail2ban-sshd", &["*sshd*".to_string()]));
        assert!(matches_tag("fail2ban-sshd", &["*-*".to_string()]));
        assert!(!matches_tag("fail2ban-sshd", &["*xyz*".to_string()]));
    }

    #[test]
    fn test_matches_tag_single_wildcard() {
        // Pattern: *
        assert!(matches_tag("fail2ban-sshd", &["*".to_string()]));
        assert!(matches_tag("any-tag", &["*".to_string()]));
        assert!(matches_tag("", &["*".to_string()]));
    }

    #[test]
    fn test_matches_tag_double_wildcard() {
        // Pattern: **
        assert!(matches_tag("fail2ban-sshd", &["**".to_string()]));
    }

    #[test]
    fn test_matches_tag_empty_pattern() {
        assert!(!matches_tag("fail2ban-sshd", &[String::new()]));
        assert!(matches_tag("", &[String::new()]));
    }

    #[test]
    fn test_matches_tag_multiple_patterns() {
        let patterns = vec![
            "web*".to_string(),
            "*sshd".to_string(),
            "exact-match".to_string(),
        ];

        assert!(matches_tag("fail2ban-sshd", &patterns)); // matches *sshd
        assert!(matches_tag("web-server", &patterns)); // matches web*
        assert!(matches_tag("exact-match", &patterns)); // matches exact
        assert!(!matches_tag("no-match", &patterns));
    }

    #[test]
    fn test_matches_tag_edge_cases() {
        // Empty tag
        assert!(matches_tag("", &["*".to_string()]));
        assert!(!matches_tag("", &["something".to_string()]));

        // Pattern with only wildcards at start
        assert!(matches_tag("test", &["*test".to_string()]));
        assert!(matches_tag("test", &["*est".to_string()]));

        // Pattern with only wildcards at end
        assert!(matches_tag("test", &["test*".to_string()]));
        assert!(matches_tag("test", &["tes*".to_string()]));
    }

    #[test]
    fn test_matches_tag_case_sensitivity() {
        // Rust string comparison is case-sensitive
        assert!(!matches_tag(
            "FAIL2BAN-SSHD",
            &["fail2ban-sshd".to_string()]
        ));
        assert!(!matches_tag("fail2ban-sshd", &["FAIL*".to_string()]));
        assert!(matches_tag("FAIL2BAN-SSHD", &["FAIL*".to_string()]));
    }

    #[test]
    fn test_matches_tag_special_characters() {
        assert!(matches_tag(
            "fail2ban-sshd.local",
            &["*sshd.local".to_string()]
        ));
        assert!(matches_tag("192.168.1.1", &["192.*".to_string()]));
        assert!(matches_tag("test_tag-123", &["*_tag*".to_string()]));
    }

    #[test]
    fn test_matches_tag_no_patterns() {
        // Empty pattern list should not match anything
        assert!(!matches_tag("fail2ban-sshd", &[]));
        assert!(!matches_tag("anything", &[]));
    }
}
