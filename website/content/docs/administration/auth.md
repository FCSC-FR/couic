---
title: Authentication and Authorization
linkTitle: Authentication and Authorization
description: "Configure Couic API authentication with tokens and RBAC. Manage client access with role-based permissions."
keywords: ["Couic", "authentication", "authorization", "RBAC", "API tokens"]
images: ["/images/couic-og.png"]
prev: /docs/administration/
next: /docs/administration/reverse-proxy
weight: 1
---

All API calls to Couic require an authentication token. Couic provides a straightforward authentication and authorization mechanism to control access to its API.

## Client file

Client definitions are stored as TOML files in Couic’s working directory.

{{< filetree/container >}}
  {{< filetree/folder name="var" >}}
    {{< filetree/folder name="lib" >}}
      {{< filetree/folder name="couic" >}}
        {{< filetree/folder name="rbac" >}}
          {{< filetree/folder name="clients" >}}
            {{< filetree/file name="couicctl.toml" >}}
            {{< filetree/file name="monitoring.toml" >}}
          {{< /filetree/folder >}}
        {{< /filetree/folder >}}
        {{< filetree/folder name="sets" >}}
          {{< filetree/folder name="drop" >}}
          {{< /filetree/folder >}}
          {{< filetree/folder name="ignore" >}}
          {{< /filetree/folder >}}
        {{< /filetree/folder >}}
      {{< /filetree/folder >}}
    {{< /filetree/folder >}}
  {{< /filetree/folder >}}
{{< /filetree/container >}}

Each file is named after the client and contains its authentication token ([UUIDv4](https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-4)) and associated group.

For security, client files must be restricted so that only the couic user has read/write access (chmod 600).

{{< callout type="warning" >}}
Couic verifies the validity of file permissions, the token format, and the uniqueness of tokens.
If any errors are detected, Couic will refuse to start, or a log entry will be generated to indicate the issue.
{{< /callout >}}

Example of client file:

```toml {filename="/var/lib/couic/rbac/clients/monitoring.toml"}
token = "ae976197-2602-447d-a281-b29e20abb7c1"
group = "monitoring"
```

### Default client `couicctl`

When Couic starts, it automatically creates a default client file for `couicctl` if it does not already exist.
This command-line tool is assigned to the `admin` group, granting it full administrative privileges (See [RBAC](auth.html#role-based-access-control-rbac)).

## Role-Based Access Control (RBAC)

Each client/token is associated with a user group, which is currently hardcoded within the application according to the following matrix of permissions:

| Action/Role           | `admin` | `clientrw` | `clientro` | `peering` | `monitoring` |
|-----------------------|:-------:|:-----------:|:-----------:|:---------:|:------------:|
| client `add`          | ✅      | ❌          | ❌          | ❌        | ❌           |
| client `get`          | ✅      | ❌          | ❌          | ❌        | ❌           |
| client `list`         | ✅      | ❌          | ❌          | ❌        | ❌           |
| client `delete`       | ✅      | ❌          | ❌          | ❌        | ❌           |
| drop/ignore `add`     | ✅      | ✅          | ❌          | ❌        | ❌           |
| drop/ignore `get`     | ✅      | ✅          | ✅          | ❌        | ❌           |
| drop/ignore `list`    | ✅      | ✅          | ✅          | ❌        | ❌           |
| drop/ignore `delete`  | ✅      | ✅          | ❌          | ❌        | ❌           |
| drop `peer`           | ✅      | ❌          | ❌          | ✅        | ❌           |
| stats `get`           | ✅      | ❌          | ❌          | ❌        | ✅           |
| stats `list`          | ✅      | ❌          | ❌          | ❌        | ✅           |
| sets `add`            | ✅      | ✅          | ❌          | ❌        | ❌           |
| sets `get`            | ✅      | ✅          | ✅          | ❌        | ❌           |
| sets `list`           | ✅      | ✅          | ✅          | ❌        | ❌           |
| sets `delete`         | ✅      | ✅          | ❌          | ❌        | ❌           |
| sets `reload`         | ✅      | ✅          | ❌          | ❌        | ❌           |

## Manage client using CLI

### Add a new client to `clientrw` group

```bash {filename="command"}
couicctl clients add -n superclient -g clientrw
```

```bash {filename="output"}
┌─────────────┬──────────┬──────────────────────────────────────┐
│ Name        ┆ Group    ┆ Token                                │
╞═════════════╪══════════╪══════════════════════════════════════╡
│ superclient ┆ clientrw ┆ 01115f88-fd3d-4fbd-b205-44c90e81dae5 │
└─────────────┴──────────┴──────────────────────────────────────┘
```

### List all clients

```bash {filename="command"}
couicctl clients list
```

```bash {filename="output"}
┌─────────────┬────────────┬──────────────────────────────────────┐
│ Name        ┆ Group      ┆ Token                                │
╞═════════════╪════════════╪══════════════════════════════════════╡
│ superclient ┆ clientrw   ┆ 01115f88-fd3d-4fbd-b205-44c90e81dae5 │
├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ prometheus  ┆ monitoring ┆ d6ac883a-8050-4408-bf1e-5b07e9965191 │
├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ couicctl    ┆ admin      ┆ 79deb94f-5dd1-417f-8842-667d8dff4480 │
└─────────────┴────────────┴──────────────────────────────────────┘
```

### Delete a client

```bash {filename="command"}
couicctl clients delete prometheus
```

{{< callout type="info" >}}
`couicctl` provides full control of Couic through its REST API. For more details, see the [couicctl reference](/docs/reference/couicctl).
{{< /callout >}}

