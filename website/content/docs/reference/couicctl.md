# Command-Line Help for `couicctl`

This document contains the help content for the `couicctl` command-line program.

**Command Overview:**

* [`couicctl`↴](#couicctl)
* [`couicctl clients`↴](#couicctl-clients)
* [`couicctl clients add`↴](#couicctl-clients-add)
* [`couicctl clients inspect`↴](#couicctl-clients-inspect)
* [`couicctl clients list`↴](#couicctl-clients-list)
* [`couicctl clients delete`↴](#couicctl-clients-delete)
* [`couicctl stats`↴](#couicctl-stats)
* [`couicctl stats global`↴](#couicctl-stats-global)
* [`couicctl stats drop`↴](#couicctl-stats-drop)
* [`couicctl stats ignore`↴](#couicctl-stats-ignore)
* [`couicctl sets`↴](#couicctl-sets)
* [`couicctl sets list`↴](#couicctl-sets-list)
* [`couicctl sets inspect`↴](#couicctl-sets-inspect)
* [`couicctl sets create`↴](#couicctl-sets-create)
* [`couicctl sets update`↴](#couicctl-sets-update)
* [`couicctl sets delete`↴](#couicctl-sets-delete)
* [`couicctl sets reload`↴](#couicctl-sets-reload)
* [`couicctl drop`↴](#couicctl-drop)
* [`couicctl drop add`↴](#couicctl-drop-add)
* [`couicctl drop delete`↴](#couicctl-drop-delete)
* [`couicctl drop list`↴](#couicctl-drop-list)
* [`couicctl drop inspect`↴](#couicctl-drop-inspect)
* [`couicctl ignore`↴](#couicctl-ignore)
* [`couicctl ignore add`↴](#couicctl-ignore-add)
* [`couicctl ignore delete`↴](#couicctl-ignore-delete)
* [`couicctl ignore list`↴](#couicctl-ignore-list)
* [`couicctl ignore inspect`↴](#couicctl-ignore-inspect)

## `couicctl`

Control couic firewall

**Usage:** `couicctl [OPTIONS] [COMMAND]`

###### **Subcommands:**

* `clients` — Manage clients
* `stats` — Display statistics
* `sets` — Control sets
* `drop` — Control drop policy
* `ignore` — Control ignore policy

###### **Options:**

* `-c`, `--config <FILE>` — Path to config file

  Default value: `/etc/couic/couicctl.toml`



## `couicctl clients`

Manage clients

**Usage:** `couicctl clients <COMMAND>`

###### **Subcommands:**

* `add` — Add client
* `inspect` — Inspect client
* `list` — List clients
* `delete` — Remove client



## `couicctl clients add`

Add client

**Usage:** `couicctl clients add [OPTIONS] --name <NAME> --group <GROUP>`

###### **Options:**

* `-n`, `--name <NAME>` — Client name. Valid characters are a-zA-Z0-9-_ and max length is 64
* `-g`, `--group <GROUP>` — Client group. Expected values: admin, clientro, clientrw, monitoring, peering
* `--json`



## `couicctl clients inspect`

Inspect client

**Usage:** `couicctl clients inspect [OPTIONS] <NAME>`

###### **Arguments:**

* `<NAME>`

###### **Options:**

* `--json`



## `couicctl clients list`

List clients

**Usage:** `couicctl clients list [OPTIONS]`

###### **Options:**

* `-q`, `--quiet`
* `--json`



## `couicctl clients delete`

Remove client

**Usage:** `couicctl clients delete <NAME>`

###### **Arguments:**

* `<NAME>`



## `couicctl stats`

Display statistics

**Usage:** `couicctl stats <COMMAND>`

###### **Subcommands:**

* `global` — Display global statistics
* `drop` — Display drop statistics per tag
* `ignore` — Display ignore statistics per tag



## `couicctl stats global`

Display global statistics

**Usage:** `couicctl stats global [OPTIONS]`

###### **Options:**

* `-l`, `--live`
* `--json`



## `couicctl stats drop`

Display drop statistics per tag

**Usage:** `couicctl stats drop [OPTIONS]`

###### **Options:**

* `--json`



## `couicctl stats ignore`

Display ignore statistics per tag

**Usage:** `couicctl stats ignore [OPTIONS]`

###### **Options:**

* `--json`



## `couicctl sets`

Control sets

**Usage:** `couicctl sets <COMMAND>`

###### **Subcommands:**

* `list` — List sets for a policy
* `inspect` — Inspect a specific set
* `create` — Create a new set
* `update` — Update a set (replaces all entries)
* `delete` — Delete a set
* `reload` — Reload sets into eBPF maps



## `couicctl sets list`

List sets for a policy

**Usage:** `couicctl sets list <POLICY>`

###### **Arguments:**

* `<POLICY>` — Policy (drop or ignore)



## `couicctl sets inspect`

Inspect a specific set

**Usage:** `couicctl sets inspect <POLICY> <NAME>`

###### **Arguments:**

* `<POLICY>` — Policy (drop or ignore)
* `<NAME>` — Set name



## `couicctl sets create`

Create a new set

**Usage:** `couicctl sets create [OPTIONS] <POLICY> <NAME> [ENTRIES]...`

###### **Arguments:**

* `<POLICY>` — Policy (drop or ignore)
* `<NAME>` — Set name
* `<ENTRIES>` — CIDR entries

###### **Options:**

* `--from-asn <FROM_ASN>` — Import prefixes from ASN via RIPE NCC RIPEstat (e.g., 200373 or AS200373).
* `--from-file <FROM_FILE>` — Import CIDRs from file (one per line, # for comments)



## `couicctl sets update`

Update a set (replaces all entries)

**Usage:** `couicctl sets update <POLICY> <NAME> [ENTRIES]...`

###### **Arguments:**

* `<POLICY>` — Policy (drop or ignore)
* `<NAME>` — Set name
* `<ENTRIES>` — CIDR entries



## `couicctl sets delete`

Delete a set

**Usage:** `couicctl sets delete <POLICY> <NAME>`

###### **Arguments:**

* `<POLICY>` — Policy (drop or ignore)
* `<NAME>` — Set name



## `couicctl sets reload`

Reload sets into eBPF maps

**Usage:** `couicctl sets reload`



## `couicctl drop`

Control drop policy

**Usage:** `couicctl drop <COMMAND>`

###### **Subcommands:**

* `add` — Add entry to drop list
* `delete` — Remove entry from drop list
* `list` — List entries in drop list
* `inspect` — Inspect entry in drop list



## `couicctl drop add`

Add entry to drop list

**Usage:** `couicctl drop add [OPTIONS] <CIDR>`

###### **Arguments:**

* `<CIDR>` — CIDR block to add to the drop list, e.g., 192.168.0.0/24

###### **Options:**

* `-t`, `--tag <TAG>` — Tag for the entry. Valid characters are a-zA-Z0-9-_ and max length is 64

  Default value: `couicctl`
* `-e`, `--expiration <EXPIRATION>` — Duration from now until the entry expires, with explicit units (e.g., 30s, 1m, 1h30m, 2d). Bare numbers other than 0 are not accepted. Use 0 or omit this option for no expiration. The CLI converts the duration to a Unix timestamp in seconds for the API.

  Default value: `0`
* `--json`



## `couicctl drop delete`

Remove entry from drop list

**Usage:** `couicctl drop delete <CIDR>`

###### **Arguments:**

* `<CIDR>`



## `couicctl drop list`

List entries in drop list

**Usage:** `couicctl drop list [OPTIONS]`

###### **Options:**

* `-q`, `--quiet`
* `-t`, `--tags <TAGS>` — Filter entries by tags. Supports wildcards (*). Multiple tags can be specified, separated by commas. Quote wildcards to prevent shell expansion (e.g., -t '*').
* `--json`



## `couicctl drop inspect`

Inspect entry in drop list

**Usage:** `couicctl drop inspect [OPTIONS] <CIDR>`

###### **Arguments:**

* `<CIDR>`

###### **Options:**

* `--json`



## `couicctl ignore`

Control ignore policy

**Usage:** `couicctl ignore <COMMAND>`

###### **Subcommands:**

* `add` — Add entry to ignore list
* `delete` — Remove entry from ignore list
* `list` — List entries in ignore list
* `inspect` — Inspect entry in ignore list



## `couicctl ignore add`

Add entry to ignore list

**Usage:** `couicctl ignore add [OPTIONS] <CIDR>`

###### **Arguments:**

* `<CIDR>` — CIDR block to add to the ignore list, e.g., 192.168.0.0/24

###### **Options:**

* `-t`, `--tag <TAG>` — Tag for the entry. Valid characters are a-zA-Z0-9-_ and max length is 64
* `-e`, `--expiration <EXPIRATION>` — Duration from now until the entry expires, with explicit units (e.g., 30s, 1m, 1h30m, 2d). Bare numbers other than 0 are not accepted. Use 0 or omit this option for no expiration. The CLI converts the duration to a Unix timestamp in seconds for the API.

  Default value: `0`
* `--json`



## `couicctl ignore delete`

Remove entry from ignore list

**Usage:** `couicctl ignore delete <CIDR>`

###### **Arguments:**

* `<CIDR>`



## `couicctl ignore list`

List entries in ignore list

**Usage:** `couicctl ignore list [OPTIONS]`

###### **Options:**

* `-q`, `--quiet`
* `-t`, `--tags <TAGS>` — Filter entries by tags. Supports wildcards (*). Multiple tags can be specified, separated by commas. Quote wildcards to prevent shell expansion (e.g., -t '*').
* `--json`



## `couicctl ignore inspect`

Inspect entry in ignore list

**Usage:** `couicctl ignore inspect [OPTIONS] <CIDR>`

###### **Arguments:**

* `<CIDR>`

###### **Options:**

* `--json`



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>

