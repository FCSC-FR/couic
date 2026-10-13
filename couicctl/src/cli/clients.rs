use clap::{Args, Subcommand};
use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL};

use client::CouicClient;
use common::{Client, ClientName, ClientRaw, Group};

use super::{Command, CommandError};

#[derive(Args, Debug)]
pub struct ClientsCommand {
    #[command(subcommand)]
    command: ClientsSubCommand,
}

#[derive(Subcommand, Debug)]
#[command(about = "Manage clients")]
enum ClientsSubCommand {
    #[command(about = "Add client")]
    Add {
        #[arg(
            short,
            long,
            help = "Client name",
            long_help = "Client name. Valid characters are a-zA-Z0-9-_ and max length is 64"
        )]
        name: ClientName,
        #[arg(
            short = 'g',
            long,
            help = "Client group",
            long_help = "Client group. Expected values: admin, clientro, clientrw, monitoring, peering"
        )]
        group: Group,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Inspect client")]
    Inspect {
        name: ClientName,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "List clients")]
    List {
        #[arg(short, long)]
        quiet: bool,
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
    },
    #[command(about = "Remove client")]
    Delete { name: ClientName },
}

impl Command for ClientsCommand {
    fn execute(&self, client: &mut CouicClient) -> Result<(), CommandError> {
        match &self.command {
            ClientsSubCommand::Add { name, group, json } => {
                let client_request = ClientRaw {
                    name: name.clone(),
                    group: group.clone(),
                };
                let clt = client.clients().add(&client_request)?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&clt)?);
                } else {
                    print_client(clt);
                }
            }
            ClientsSubCommand::Inspect { name, json } => {
                let clt = client.clients().get(name)?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&clt)?);
                } else {
                    print_client(clt);
                }
            }
            ClientsSubCommand::List { quiet, json } => {
                let clients = client.clients().list()?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&clients)?);
                } else {
                    print_clients(clients, *quiet);
                }
            }
            ClientsSubCommand::Delete { name } => {
                client.clients().delete(name)?;
            }
        }
        Ok(())
    }
}

fn print_client(client: Client) {
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Name", "Group", "Token"]);

    table.add_row(vec![
        Cell::new(client.name),
        Cell::new(client.group),
        Cell::new(client.token),
    ]);

    println!("{table}");
}

fn print_clients(clients: Vec<Client>, quiet: bool) {
    if quiet {
        for c in clients {
            println!("{}", c.name);
        }
    } else {
        let mut table = Table::new();
        table
            .load_style(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["Name", "Group", "Token"]);

        for c in clients {
            table.add_row(vec![
                Cell::new(c.name),
                Cell::new(c.group),
                Cell::new(c.token),
            ]);
        }
        println!("{table}");
    }
}
