# ADR 0006: Cloud editions and evolution boundary

Status: accepted — 2026-08-09

## Decision

The self-hosted cloud and official cloud are products built from a shared, versioned synchronization contract, not deployment profiles that silently gain each other's capabilities.

The public self-hosted artifact is built with `--no-default-features --features self-hosted`. It includes encrypted synchronization, account/device management, recovery settings, audit metadata, and the administration panel. It does not compile the update service, release publication route, update package parser, official update key, official deployment tooling, or proprietary client.

The private official deployment is built with `--no-default-features --features official-cloud`. Until the official-cloud v2 asymmetric protocol is complete, it may reuse the audited v1 cloud core. The v2 implementation will use a distinct API namespace and cryptographic-suite identifier: TLS plus ephemeral X25519, HKDF-SHA256 key derivation, per-device Ed25519 identities, canonical signed requests and important responses/events, key identifiers and rotation/revocation, timestamps, nonces, idempotency rules, and AEAD payload protection where application-level encryption is required. It is then extracted into a private official-cloud line while the self-hosted v1 contract remains open and compatible.

## Compatibility rules

- Existing `/v1` request and ciphertext envelope semantics are never changed in place.
- Additive fields are optional and old readers must ignore unknown fields.
- Breaking behavior uses a new API/protocol version and an explicit migration window.
- Cryptographic algorithms and transcript formats are selected by a versioned suite; a server must never silently reinterpret a suite already accepted by a released client.
- Capability discovery is additive. Clients choose only advertised capabilities they understand and retain an explicit fallback or minimum-supported-version decision.
- Database migrations are forward-only; upgrades preserve the database volume and cloud identity key.
- Cloud identity keys are deployment state, never image or source state.
- The one-click installer pins a source ref, keeps prior source releases, and switches the active release atomically.
- Public export is allow-list based and fails if client sources, private symbols, update-service files, credentials or key material appear.

These boundaries allow the desktop client, public self-hosted service and private official cloud to evolve independently while sharing stable data formats where interoperability is intentional.
