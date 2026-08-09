<!-- BEAUTIFIED -->

<p align="center">
  <a href="README.md">中文</a> · English
</p>

<h1 align="center">HeartLink Self-Hosted Cloud</h1>

<p align="center">
  <strong>A self-hosted HeartLink cloud for accounts, device management, and end-to-end ciphertext synchronization.</strong>
  <br />
  <em>Local control · Opaque ciphertext storage · One-command Linux deployment</em>
</p>

<p align="center">
  <a href="#quick-start"><img src="https://img.shields.io/badge/Quick_Start-16A34A?style=for-the-badge" alt="Quick Start" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0--only-EAB308?style=for-the-badge" alt="License" /></a>
</p>

<p align="center">
  <a href="https://github.com/HEARTHROBXD/HeartLink-Self-Hosted/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/HEARTHROBXD/HeartLink-Self-Hosted/ci.yml?branch=main&style=flat&label=CI" alt="Build Status" /></a>
  <img src="https://img.shields.io/badge/Rust_1.85+-000000?style=flat&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Axum_0.8-7C3AED?style=flat" alt="Axum" />
  <img src="https://img.shields.io/badge/MySQL_8.4-4479A1?style=flat&logo=mysql&logoColor=white" alt="MySQL" />
  <img src="https://img.shields.io/badge/Docker_Compose-2496ED?style=flat&logo=docker&logoColor=white" alt="Docker Compose" />
</p>

## Features

| Feature | Description |
|---|---|
| Opaque ciphertext sync | Stores versioned ciphertext produced by the client and preserves conflicting revisions. Master passwords, vault keys, and plaintext server credentials are never uploaded. |
| Account and device management | Provides registration, authentication, sessions, device enrollment, revocation, and a separate device-control channel. |
| Administration panel | Uses a dedicated administration port for user, device, recovery, and audit management. |
| Cloud identity verification | Generates an Ed25519 identity during installation and outputs the public key for trusted client enrollment. |
| Unified IP endpoints | Publishes the cloud API and administration panel on configurable IPv4 addresses; domains, certificates, and reverse proxies are fully operator-managed. |
| Evolvable protocol boundary | Keeps APIs under `/v1`, uses forward-only database migrations, and maintains shared models and sync protocols as separate packages. |

> [!IMPORTANT]
> This repository does not contain the HeartLink desktop client, official-cloud operations modules, or software-update distribution. SSH, SFTP, and RDP traffic connects directly from the client to the target server and never passes through this cloud.

## Quick Start

### Prerequisites

- An `x86_64` or `arm64` Linux host with root access.
- Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, openSUSE, SLES, and Arch Linux are supported.
- Configure the host firewall before exposing the service. HTTPS requires an operator-managed reverse proxy and a trusted certificate matching the selected IP address or domain.

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/HEARTHROBXD/HeartLink-Self-Hosted/main/install.sh | sudo bash
```

The installer does not distinguish between LAN and Internet deployment, and it does not request domains or certificates. By default, the cloud API and administration panel are published on every IPv4 interface:

```text
http://SERVER_IP:8787
http://SERVER_IP:8789
```

To restrict either service to a specific interface, provide its IPv4 address during installation or upgrade:

```bash
curl -fsSL https://raw.githubusercontent.com/HEARTHROBXD/HeartLink-Self-Hosted/main/install.sh | \
  sudo bash -s -- install \
    --publish-ip 192.168.1.20 \
    --panel-publish-ip 192.168.1.20
```

### Configure HTTPS

Operators manage HTTPS and domains independently. A reverse proxy may expose an IP address or a domain and forward traffic to the same IP upstreams: `http://SERVER_IP:8787` for the cloud API and `http://SERVER_IP:8789` for the administration panel. When using `https://IP`, the certificate must contain that IP in its Subject Alternative Name and be trusted by the client system; the client never bypasses certificate validation.

### Save the installation result

When installation completes, the terminal and `/opt/heartlink-cloud/install-result.txt` show IP-based cloud and panel URLs, the random administration password, the Ed25519 cloud identity public key, an optional SSH tunnel command, and the HTTPS upstream addresses. Only root can read this file.

## Usage

### Check status

```bash
sudo /opt/heartlink-cloud/current/install.sh status
```

### Upgrade atomically

```bash
sudo /opt/heartlink-cloud/current/install.sh upgrade
```

An upgrade builds a new append-only release directory and atomically switches `current`, while preserving database volumes, configuration, and the original cloud identity private key.

### Uninstall

```bash
sudo /opt/heartlink-cloud/current/install.sh uninstall
```

A normal uninstall preserves data. Only the explicit `--purge-data` option permanently removes Docker volumes, identity keys, and configuration.

## Architecture

The client encrypts data before synchronization. The self-hosted service handles authentication, device control, ciphertext revisions, and administration.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'fontSize': '14px', 'lineColor': '#64748B'}}}%%
graph LR
    A[HeartLink Client<br/>Not included] -->|Trusted private HTTP| C[Cloud API<br/>IP :8787]
    A -->|HTTPS + IP or domain| B[Operator-managed proxy<br/>TLS termination]
    B -->|HTTP IP upstream| C
    B -->|HTTP IP upstream| D[Admin Panel<br/>IP :8789]
    C --> E[Account and Device Control<br/>Argon2id / Ed25519]
    C --> F[(MySQL 8.4<br/>Opaque Ciphertext)]
    D --> F
    A -. Direct SSH / SFTP / RDP .-> G[Target Server<br/>Cloud bypassed]

    classDef client fill:#3B82F6,stroke:#2563EB,color:#fff,stroke-width:2px
    classDef gateway fill:#F59E0B,stroke:#D97706,color:#fff,stroke-width:2px
    classDef service fill:#10B981,stroke:#059669,color:#fff,stroke-width:2px
    classDef auth fill:#F97316,stroke:#EA580C,color:#fff,stroke-width:2px
    classDef data fill:#8B5CF6,stroke:#7C3AED,color:#fff,stroke-width:2px
    classDef external fill:#F43F5E,stroke:#E11D48,color:#fff,stroke-width:2px

    class A client
    class B gateway
    class C,D service
    class E auth
    class F data
    class G external
```

## Configuration

The installer writes runtime configuration to `/opt/heartlink-cloud/.env`. The table lists the most commonly used options.

| Variable | Description | Default |
|---|---|---|
| `HEARTLINK_DATABASE_NAME` | MySQL database name. | `heartlink` |
| `HEARTLINK_DATABASE_USER` | MySQL application account. | `heartlink` |
| `HEARTLINK_DATABASE_PASSWORD` | MySQL application password. | Randomly generated |
| `HEARTLINK_PUBLISH_IP` | IPv4 publish address for cloud port `8787`; `0.0.0.0` selects every IPv4 interface. | `0.0.0.0` |
| `HEARTLINK_PANEL_PUBLISH_IP` | IPv4 publish address for panel port `8789`; set a specific interface or `127.0.0.1` when required. | `0.0.0.0` |
| `HEARTLINK_REGISTRATION_ENABLED` | Enables new account registration. | `true` |
| `HEARTLINK_RECOVERY_EMAIL_WEBHOOK` | HTTPS webhook for email recovery codes. | Unset |
| `HEARTLINK_RECOVERY_SMS_WEBHOOK` | HTTPS webhook for SMS recovery codes. | Unset |
| `HEARTLINK_RECOVERY_WEBHOOK_TOKEN` | Optional Bearer token for recovery webhooks. | Unset |
| `HEARTLINK_RECOVERY_PEPPER` | Independent random value of at least 32 characters for recovery-code digests. | Randomly generated |

See the [Linux self-hosting guide](docs/SELF_HOSTING_LINUX.md) for complete configuration, 1Panel integration, and backup instructions.

## API

The public protocol is defined in the [OpenAPI 3.1 specification](docs/api/openapi.yaml). Except for health, registration, and login, endpoints require the corresponding Bearer or device-control credential.

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `GET` | `/health` | Check service and protocol versions. | None |
| `POST` | `/v1/auth/register` | Register an account and create a session. | None |
| `POST` | `/v1/auth/login` | Authenticate an account and create a session. | None |
| `DELETE` | `/v1/auth/session` | Revoke the current session. | Bearer |
| `GET / POST` | `/v1/devices` | List or enroll devices. | Bearer |
| `DELETE` | `/v1/devices/{device_id}` | Revoke a device using the account password. | Bearer |
| `GET / POST` | `/v1/devices/{device_id}/control` | Poll or acknowledge device-control commands. | Device-control token |
| `POST` | `/v1/sync/push` | Submit one ciphertext revision or return a conflict. | Bearer |
| `GET` | `/v1/sync/pull` | Incrementally retrieve ciphertext revisions and tombstones. | Bearer |

## Project Structure

```text
.
├── .github/workflows/       # CI configuration
├── apps/server/             # Axum cloud service and admin panel
│   ├── migrations_mysql/    # Forward-only MySQL migrations
│   └── src/                 # API, handshake, and administration logic
├── docs/                    # Deployment, security, OpenAPI, and ADRs
├── infra/docker/            # Compose and 1Panel configuration
├── packages/
│   ├── shared_models/       # Cross-component data models
│   └── sync_protocol/       # Versioned synchronization protocol
├── install.sh               # Linux installation and operations entry point
├── Cargo.toml               # Rust workspace
└── SOURCE_MANIFEST.sha256   # Hash manifest for the public export
```

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | Rust 2024, Axum 0.8, Tokio | HTTP services, concurrent runtime, and administration panel. |
| Data | SQLx 0.8, MySQL 8.4 | Data access, migrations, and persistence. |
| Security | Argon2id, Ed25519, BLAKE3 | Password verification, cloud identity, and token digests. |
| Infrastructure | Docker Compose | Container orchestration, port publishing, and database network isolation. |
| Interface | REST, OpenAPI 3.1 | Versioned `/v1` API and protocol documentation. |
| Validation | Cargo test, Clippy, GitHub Actions | Formatting, static analysis, tests, and image builds. |

## Deployment

The one-command installer pulls source from this repository, builds the self-hosted-only image on the server, and generates independent passwords and identity keys.

- Use the [Docker Compose configuration](infra/docker/compose.yaml) for MySQL and HeartLink; both application ports support binding to a selected IPv4 address.
- Use the [1Panel configuration](infra/docker/compose.1panel.yaml) with an existing MySQL container and Docker network.
- Domains, WAFs, TLS certificates, and reverse proxies are outside the installer boundary. Operators may use Nginx, Caddy, 1Panel, SafeLine, or another gateway with IP upstreams.
- Use [GitHub Actions](.github/workflows/ci.yml) to validate formatting, Clippy, tests, Docker builds, and the public-source boundary.
- Read the [security policy](SECURITY.md) before production deployment, and back up `/opt/heartlink-cloud/secrets`, configuration, and Docker volumes.

## Contributing

1. Fork the repository and create a feature branch from `main`.
2. Follow the [contribution guide](CONTRIBUTING.md), preserve protocol compatibility, and add tests for behavior changes.
3. Run the validation commands:

   ```bash
   cargo fmt --all -- --check
   cargo clippy -p heartlink-server --no-default-features --features self-hosted --all-targets -- -D warnings
   cargo test -p heartlink-server --no-default-features --features self-hosted
   docker build -f apps/server/Dockerfile .
   ```

4. Commit the changes and open a Pull Request. Never commit real hosts, credentials, private keys, access tokens, or production ciphertext.

## License

The root repository is licensed under [AGPL-3.0-only](LICENSE). Shared models and the synchronization protocol use `Apache-2.0`, while documentation uses `CC-BY-4.0`; see the [component license notes](LICENSES/README.md) for directory-level boundaries.
