# Third-party notices

Dependencies are not redistributed by this source tree. Their licenses remain with their authors.

Initial direct dependency review:

| Component | Purpose | License family |
|---|---|---|
| Flutter / Dart | Cross-platform client | BSD-3-Clause |
| Riverpod | State and dependency injection | MIT |
| GoRouter | Declarative routing | BSD-3-Clause |
| dartssh2 2.22.x | SSH, PTY and SFTP transport | MIT |
| xterm.dart 4.x | Terminal emulation and rendering | MIT |
| enough_convert 1.6.x | GBK and Big5 terminal codecs | MPL-2.0 |
| win32 6.x / ffi 2.x | Windows DPAPI bindings | BSD-3-Clause |
| Axum / Tokio / Tower | HTTP runtime | MIT |
| SQLx | MySQL and SQLite access | MIT OR Apache-2.0 |
| RustCrypto argon2, chacha20poly1305 | KDF and AEAD | MIT OR Apache-2.0 |
| serde / uuid / time | Serialization and identifiers | MIT OR Apache-2.0 (typical; verify lockfile) |

Before a release, generate a lockfile-based SBOM/license report (`cargo deny`, `cargo about`, Flutter/Dart license collection), review every transitive dependency, and replace this preliminary table with exact versions and notices.
