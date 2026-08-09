# Security policy and threat model

## Security properties

- Zero-knowledge synchronization: the service receives only versioned ciphertext envelopes.
- No SSH proxying: SSH traffic travels directly between client and target host.
- Authenticated encryption: XChaCha20-Poly1305 with a unique random nonce per operation.
- Memory-hard derivation: Argon2id with parameters recorded in the envelope and bounded on decode.
- Host-key pinning: unknown keys require consent and changed keys block.
- Conflict preservation: stale updates produce an explicit conflict.
- Sensitive logging is denied by design; secrets use redacted wrappers where practical.

## Threat model

Protected against a curious sync administrator, database theft, network observation when TLS is correctly deployed, accidental stale-client overwrite, and first-use/changed-host-key ambiguity. A compromised unlocked endpoint, malicious OS, keylogger, hostile accessibility service, weak master password, or substituted client binary remains able to obtain plaintext. First connection is still vulnerable if the user trusts an attacker's fingerprint; verify it out-of-band.

Metadata leakage remains: account identifiers, device labels/platforms, record types, record sizes, timestamps, deletion state, and update frequency. A later padding option may reduce size leakage.

## Secrets handling

Master passwords and vault keys never leave the client. Platform secure storage holds only a device-scoped wrapped-key/unlock credential. Private keys must be parsed in memory and never written to a plaintext temporary file. Clipboard secrets require timed clearing, and background/idle locking is a client milestone before production readiness.

Server login passwords are independent from vault master passwords. The server stores Argon2id verifiers. Session tokens are random, are returned once, and only a BLAKE3 digest is stored.

## Cryptographic format

`crypto_core` emits a versioned envelope containing format version, algorithm identifier, nonce, ciphertext, and authenticated associated data. Unknown versions and algorithms fail closed. Cryptography is composed from audited RustCrypto crates; no custom cipher or SSH protocol is implemented.

## Vulnerability reporting

Do not open a public issue for suspected vulnerabilities. Until a dedicated private channel is published, email the repository security contact stated in the project hosting metadata. Include affected version, reproduction, and impact; do not include real credentials.

## Production gate

This prototype has not received an independent audit. Production use is blocked until real SSH transport, system key stores, memory/clipboard protections, dependency review, rate limiting, TLS deployment validation, backup/restore testing, and an external cryptographic/security assessment are complete.

