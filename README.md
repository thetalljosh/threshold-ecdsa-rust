# threshold-ecdsa-rust

A Cargo workspace containing two crates:

| Crate | Path | Description |
|-------|------|-------------|
| `gennaro-rs` | `/` (root) | Threshold ECDSA research (Gennaro et al., secp256k1 + Paillier) |
| `chat-core` | `crates/chat-core/` | Security-first Nostr NIP-17 private chat library |

---

## `chat-core` — What It Is

`chat-core` is a **UI-independent, safe-Rust** library for NIP-17 private direct messaging over the Nostr decentralized relay network. Think IRC-style chat with Signal-level client-side encryption, no central server, and no big-tech involvement.

**Design philosophy:** security boundaries and reviewable Rust first; frontend and FFI come later.

### Features

- **Opaque identity handles** — `IdentityHandle` wraps Nostr keys. `Debug` shows only the `npub`. No method ever returns a secret key.
- **Ordered inbound pipeline** — size check → parse → **BIP-340 signature verify** → kind check → NIP-44 decrypt → NIP-17 participant check → deduplication. Signature verification always precedes decryption.
- **Per-recipient gift-wrap fan-out** — one NIP-59 `kind:1059` gift wrap per recipient, plus a mandatory self-copy for sent-history recovery.
- **No custom cryptography** — all primitives delegated to the [`nostr`](https://crates.io/crates/nostr) crate (rust-nostr project): BIP-340, NIP-44, NIP-59.
- **Typed errors** — `ChatError` variants carry no plaintext or key material.
- **Trait-based interfaces** — `Keystore`, `LocalStore`, `RelayTransport` traits decouple `chat-core` from platform I/O.

### Scope and Intentional Deferrals

`chat-core` is a **library only**. The following are explicitly out of scope for this crate:

- Network I/O (relay WebSocket connections) — future `chat-transport` crate
- Persistent local storage — future `chat-store` crate
- OS keychain integration — future platform-specific crates
- Flutter/Dart or WASM FFI bindings — future `chat-ffi` / `chat-wasm` crates
- Large-group messaging (NIP-17 fan-out does not scale to large groups)
- Forward secrecy / post-compromise security (NIP-44 does not provide these)
- Frontend or UI of any kind

### Known Limitations

- **No forward secrecy.** NIP-44 encrypts with long-term keys. Compromise of a long-term key can expose stored conversations. This is a documented limitation of the current NIP-17/NIP-44 design.
- **Relay metadata.** Relays can observe sender/recipient public keys, connection IP addresses, and ciphertext sizes even though message content is encrypted.
- **Alpha dependency.** `nostr = "0.45.0-alpha.8"` is pinned while the upstream library stabilizes. Update to a reviewed stable release before any production deployment.

---

## Running Tests

```bash
# Run all workspace tests (chat-core + any tests that compile in gennaro-rs)
cargo test --workspace

# Run only chat-core tests
cargo test -p chat-core
```

> **Note on `gennaro-rs`:** The existing threshold ECDSA crate depends on `paillier = "0.2.0"` which uses `#![feature(test)]` and requires a nightly Rust toolchain to compile. The `chat-core` crate uses stable Rust and is unaffected.

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component diagram, module reference, inbound pipeline, cryptography dependency |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Protected assets, attacker capabilities, trust boundaries, safe logging rules, known limitations |

---

## `gennaro-rs` — Threshold ECDSA Research

The root crate is a proof-of-concept implementation of the Gennaro et al. threshold ECDSA protocol:

- Shamir Secret Sharing, Pedersen/Feldman commitments
- Paillier-based multiplicative-to-additive (MTA) protocol
- secp256k1 key generation and threshold signing

> **Security note:** This crate is academic research, not a production security library. The demo binary prints the aggregated private key to stdout. It is **not used** on the `chat-core` encryption or signing critical path.

---

## Workspace Structure

```
threshold-ecdsa-rust/
├── Cargo.toml              # Workspace root (also gennaro-rs package)
├── Cargo.lock              # Pinned dependency versions
├── src/                    # gennaro-rs threshold ECDSA source
│   ├── main.rs
│   ├── lib.rs
│   ├── keygen.rs
│   ├── signing.rs
│   └── ...
├── crates/
│   └── chat-core/          # NIP-17 private chat library
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── error.rs
│       │   ├── identity.rs
│       │   ├── types.rs
│       │   ├── traits.rs
│       │   ├── validation.rs
│       │   └── outbound.rs
│       └── tests/
│           └── security_tests.rs
└── docs/
    ├── ARCHITECTURE.md
    └── THREAT_MODEL.md
```
