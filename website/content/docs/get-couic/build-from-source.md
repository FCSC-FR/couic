---
title: Build from source
linkTitle: Build from source
description: "Build Couic eBPF firewall from source using Rust. Step-by-step compilation guide with make targets and local testing."
keywords: ["Couic", "build from source", "Rust", "eBPF", "compilation"]
images: ["/images/couic-og.png"]
prev: /docs/get-couic/installation
next: /docs/getting-started
weight: 4
---

## Build from source using Rust

All Linux libraries and executables of couic can be built on Linux.

### Requirements

The following elements are required to build them:

- `make` package
- The Rust toolchain installer [rustup](https://rustup.rs/)

### Make Targets

The `Makefile` contains three main targets:

- `setup`: invokes `rustup` to install all needed toolchains, targets and
  components for Rust;
- `debug`: builds non-stripped libraries and executables with debugging logs
  activated. Outputs to a repository named `debug`;
- `release`: builds stripped and optimized libraries and executables with
  informational logs. Outputs to a directory named `release`.

For example, to build the project in release mode:

```bash {filename="command"}
git clone https://github.com/FCSC-FR/couic
cd couic
make setup
make release
```

The release directory must have the following structure after compilation:

{{< filetree/container >}}
  {{< filetree/folder name="release" >}}
    {{< filetree/file name="couic" >}}
    {{< filetree/file name="couic_1.0.0-1_amd64.deb" >}}
    {{< filetree/file name="couic-1.0.0-1.x86_64.rpm" >}}
    {{< filetree/file name="couicctl" >}}
    {{< filetree/file name="couic-report" >}}
    {{< filetree/file name="couic-report_1.0.0-1_amd64.deb" >}}
    {{< filetree/file name="couic-report-1.0.0-1.x86_64.rpm" >}}
  {{< /filetree/folder >}}
{{< /filetree/container >}}

## Test locally

To test the previously compiled binaries locally, we need to create the Couic workspace and copy the Couic configuration files into it.

{{% steps %}}

### Create a working directory

```bash {filename="command"}
mkdir local
cp configs/couic*.toml local
```

### Edit Couic configuration

Edit `couic.toml` to match your environment.

```toml {filename="couic.toml"}
#==========================
# Couic Configuration File
#==========================

ifaces = ["my_eth"]           # interface where couic will be attached
working_dir = "/path_to_local_dir"                   
user = "my_user"              # current user name  
group = "my_group"            # current user group

[logging]
dir = "/path_to_local_dir"

[server]
socket = "/path_to_local_dir/couic.sock"
```

### Add required capabilities

Give the required capabilities to couic binary. These capabilities are only used at startup and are immediately dropped, allowing Couic to run as a non-privileged user (more details in [security section](security.md#privilege-management)). Then start the process.

```bash {filename="command"}
sudo setcap cap_sys_admin,cap_net_admin+ep ./release/couic
./release/couic -c local/couic.toml
```

### Configure `couicctl`

Edit `couicctl.toml` to match your environment. `rbac/clients/couicctl.toml` is automatically created at Couic's startup.

```toml {filename="couicctl.toml"}
#==========================
# Couicctl Configuration File
#==========================

# mode: local or remote
mode = "local"

# Local server configuration
socket = "/path_to_local_dir/couic.sock"
# Auth token
client_file = "/path_to_local_dir/rbac/clients/couicctl.toml"
```

### Test deployment

You should now be ready to interact with a fully functional Couic installation. Test it using `couicctl` from another terminal:

```bash {filename="command"}
./release/couicctl -c ./local/couicctl.toml
```

```txt {filename="output"}
Control couic firewall

Usage: couicctl [OPTIONS] [COMMAND]

Commands:
  clients  Manage clients
  stats    Display statistics
  sets     Control sets
  drop     Control drop policy
  ignore   Control ignore policy
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <FILE>  Path to config file [default: /etc/couic/couicctl.toml]
  -h, --help           Print help
  -V, --version        Print version
```



{{% /steps %}}






