---
title: Project Architecture
linkTitle: Project Architecture
description: "Couic architecture overview — Core daemon, eBPF/XDP program, Rust crate structure, and extensibility model for custom integrations"
keywords: ["Couic", "architecture", "Rust", "eBPF crates", "XDP program", "Aya framework", "CTF infrastructure"]
images: ["/images/couic-og.png"]
prev: /docs/reference
next: /docs/reference/security
weight: 1
---

This section provides a technical overview of the Couic project structure, its core components, and extensibility model.

## Overview

The Couic project follows a modular architecture designed around a central filtering daemon and its ecosystem of companion tools. The system is composed of two core components and optional auxiliary programs that extend functionality.

| Component | Type | Purpose | Status |
|-----------|------|---------|--------|
| `couic` | Core | eBPF filtering daemon with REST API (via `Unix Domain Socket`) | Public |
| `couicctl` | Core | Command-line administration tool | Public |
| `couic-report` | Auxiliary | Telemetry aggregation and notifications (Discord) | Public |
| `couicmon` | Auxiliary | Log-based automatic rule injection | Coming soon |
| `client` | Library | REST API client implementation | Public |
| `common` | Library | Shared types and definitions for Couic components | Public |

The following diagram illustrates the relationships between Couic components and their interactions with the network stack and external systems.

![Couic System Architecture](/images/couic-architecture.svg "Couic System Architecture")

## Core Components

### couic

The `couic` daemon is the central component of the filtering solution. It operates as a user-space program that manages eBPF maps shared with the kernel and exposes a REST API for external control.

**Key characteristics:**

- Built using the [Aya](https://github.com/aya-rs/aya-template) framework for eBPF development in Rust
- The eBPF/XDP program is compiled and embedded directly into the binary
- Attaches to network interfaces via [XDP](https://en.wikipedia.org/wiki/Express_Data_Path) at startup
- Exposes an HTTP REST API for programmatic access to filtering rules
- Manages allowlists, blocklists, and filtering policies

**Source structure:**

| Crate | Description |
|-------|-------------|
| `couic` | User-space daemon with REST API server |
| `couic-ebpf` | eBPF/XDP kernel program |

### `couicctl`

The `couicctl` command-line interface provides administrative control over Couic instances. It communicates with the daemon through the REST API and supports both local and remote management.

**Capabilities:**

- Add, remove, and list filtering rules
- Manage allowlists and blocklists
- Query daemon status and statistics
- Support for multiple output formats (table, JSON)

For detailed usage, see the [couicctl reference](/docs/reference/couicctl).

## Auxiliary Components

### `couic-report`

The `couic-report` service is a webhook endpoint that receives telemetry data from Couic instances and dispatches aggregated statistics to notification channels.

**Features:**

- Batches incoming reports over configurable intervals
- Computes statistics (total count, distinct CIDRs, top tags)
- Trait-based notification system (Discord supported, extensible)
- Threshold-based alerting with color-coded severity

For deployment instructions, see the [couic-report documentation](/docs/administration/reporting/couic-report).

### `couicmon`

The `couicmon` program monitors web server logs and automatically injects blocking rules via the Couic REST API based on configurable detection patterns.

{{< callout type="info" >}}
The `couicmon` program is not public yet, but it will be released soon.
{{< /callout >}}

## Extensibility Model

Couic is designed as a filtering backend that can be integrated with custom solutions. Users are encouraged to build their own modules using the REST API rather than modifying core components.

### Client Library

The `client` crate provides a Rust implementation of the REST API client, used internally by Couic programs. This crate can serve as a reference for implementing clients in other languages.

### Common Library

The `common` crate contains shared types and definitions used across all Couic components, including:

- CIDR and IP address normalization types
- Entry and policy definitions
- Error types and codes
- Statistics structures for eBPF maps
- Validation utilities

{{< callout type="info" >}}
The `client` and `common` crates are internal libraries and are not published on crates.io. To use them, you need to import them directly from the repository as git dependencies in your `Cargo.toml`. Rust documentation for these crates will be added soon.
{{< /callout >}}

### OpenAPI Specification

An [OpenAPI specification](/json/openapi.json) is provided to facilitate client development. This machine-readable document enables:

- Automatic client library generation
- Request validation
- Interactive API exploration via tools like [Swagger Editor](https://editor-next.swagger.io/)
