---
title: Dynamic filtering using couicctl
linkTitle: Dynamic filtering
description: "Manage Couic firewall rules dynamically with couicctl CLI. Add, remove, and list drop/ignore entries with TTL support."
keywords: ["Couic", "couicctl", "CLI", "dynamic filtering", "firewall rules"]
images: ["/images/couic-og.png"]
prev: /docs/getting-started/filtering-policies
next: /docs/getting-started/static-sets
weight: 7
---

## Overview

Couic provides a command-line tool (`couicctl`) for managing filtering policies dynamically. `couicctl` is a RESTful API client that communicates with the Couic daemon over a Unix domain socket, making it functionally equivalent to any other API client. As such, `couicctl` serves as the **reference implementation** for interacting with the Couic API.

{{< callout type="info" >}}
Keep in mind that any entries added through the CLI are temporary and will not persist after Couic restarts.
{{< /callout >}}

## Control policies

### Use `couicctl` to always allow local network:

```bash  {filename="command"}
couicctl ignore add 192.168.0.0/24
```

```txt {filename="output"}
┌────────┬────────────────┬─────┬────────────┐
│ Policy ┆ CIDR           ┆ Tag ┆ Expiration │
╞════════╪════════════════╪═════╪════════════╡
│ ignore ┆ 192.168.0.0/24 ┆     ┆ never      │
└────────┴────────────────┴─────┴────────────┘
```

### Use `couicctl` to drop incoming traffic for a single IP:

```bash  {filename="command"}
couicctl drop add 8.8.8.8/32
```

```bash {filename="output"}
┌────────┬────────────┬─────┬────────────┐
│ Policy ┆ CIDR       ┆ Tag ┆ Expiration │
╞════════╪════════════╪═════╪════════════╡
│ drop   ┆ 8.8.8.8/32 ┆     ┆ never      │
└────────┴────────────┴─────┴────────────┘
```

### Add another CIDR with a tag and a TTL of 1 minute:

```bash  {filename="command"}
couicctl drop add 3.3.3.3/24 -t "test" -e 1m
```

```txt {filename="output"}
┌────────┬────────────┬──────┬────────────┐
│ Policy ┆ CIDR       ┆ Tag  ┆ Expiration │
╞════════╪════════════╪══════╪════════════╡
│ drop   ┆ 3.3.3.3/24 ┆ test ┆ 59s        │
└────────┴────────────┴──────┴────────────┘
```

### List current drop policy entries:

```bash  {filename="command"}
couicctl drop list
```

```txt {filename="output"}
┌────────┬────────────┬──────┬────────────┐
│ Policy ┆ CIDR       ┆ Tag  ┆ Expiration │
╞════════╪════════════╪══════╪════════════╡
│ drop   ┆ 3.3.3.3/24 ┆ test ┆ 55s        │
├╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┤
│ drop   ┆ 8.8.8.8/32 ┆      ┆ never      │
└────────┴────────────┴──────┴────────────┘
```

### Display filtering statistics:

```bash  {filename="command"}
couicctl stats global
```

```txt {filename="output"}
Drop CIDR Count: 1
Ignore CIDR Count: 0
XDP Stats:
  Action: XDP_ABORTED
    RX Packets: 0
    RX Bytes: 0
  Action: XDP_DROP
    RX Packets: 4925
    RX Bytes: 411826
  Action: XDP_PASS
    RX Packets: 360665
    RX Bytes: 62089426
  Action: XDP_REDIRECT
    RX Packets: 0
    RX Bytes: 0
  Action: XDP_TX
    RX Packets: 0
    RX Bytes: 0
```

{{< callout type="info" >}}
`couicctl` provides full control of Couic through its REST API. For more details, see the [couicctl reference](/docs/reference/couicctl).
{{< /callout >}}