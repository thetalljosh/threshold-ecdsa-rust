# Architecture

> **Status:** Draft v0.1 — describes the current `chat-core` crate and its planned integration points.

---

## 1. Overview

This repository contains two Rust crates in a Cargo workspace:

| Crate | Purpose |
|-------|---------|
| `gennaro-rs` (root) | Threshold ECDSA research (preserved; not on the chat critical path) |
| `crates/chat-core` | Security-first Nostr NIP-17 private chat library |

The goal is an **IRC-style, client-side-encrypted private chat** with no central provider and strong security boundaries, inspired by Signal's confidentiality principles but built on the Nostr decentralised relay network.

---

## 2. Design Principles

1. **Security before UX.** The library is reviewed first; UI and FFI come later.
2. **No custom cryptography.** All cryptographic operations delegate to the [`nostr`](https://crates.io/crates/nostr) crate (rust-nostr project): BIP-340 Schnorr signing, NIP-44 AEAD, NIP-59 gift wrapping.
3. **Minimal attack surface.** `chat-core` is a `lib` crate with no network I/O, no async runtime dependency, and no UI framework. It can be tested in isolation.
4. **Opaque secrets.** No public API ever returns a private key, NIP-44 key, or seed phrase. The `IdentityHandle` type enforces this at compile time.
5. **Ordered validation.** Signature verification always precedes decryption (see §5).
6. **Explicit boundaries.** Each layer communicates through typed traits (`Keystore`, `LocalStore`, `RelayTransport`); implementations live outside `chat-core`.

---

## 3. Component Diagram

```
┌──────────────────────────────────────────────────────────┐
│  Future UI layers (Flutter / Angular / CLI)              │
│  - Calls chat-core through a narrow FFI or WASM API      │
│  - Receives only: ChatMessage, OutboundPlan, ChatError   │
│  - Never holds nsec, never builds gift wraps             │
└────────────────────────┬─────────────────────────────────┘
                         │ typed commands
┌────────────────────────▼─────────────────────────────────┐
│  chat-core  (crates/chat-core)                           │
│                                                          │
│  identity.rs   — IdentityHandle (opaque, ZeroizeOnDrop)  │
│  validation.rs — inbound pipeline (7 ordered steps)      │
│  outbound.rs   — per-recipient gift-wrap fan-out         │
│  traits.rs     — ChatSigner, Keystore, LocalStore,       │
│                   RelayTransport trait definitions        │
│  types.rs      — ChatMessage, OutboundPlan, MessageId,   │
│                   DeduplicationSet, RelayUrl, …          │
│  error.rs      — ChatError (typed, no plaintext leaks)   │
└───────┬───────────────────┬──────────────────────────────┘
        │                   │
┌───────▼───────┐   ┌───────▼────────────────────────────┐
│ Keystore impl │   │ LocalStore impl                     │
│ (future crate)│   │ (future crate, platform-native      │
│ OS Keychain / │   │  encrypted storage)                 │
│ Secure Enclave│   └───────┬────────────────────────────┘
└───────────────┘           │
                    ┌───────▼────────────────────────────┐
                    │ RelayTransport impl                 │
                    │ (future crate, nostr-sdk relay pool)│
                    └───────┬────────────────────────────┘
                            │ WSS + NIP-42 auth
                    ┌───────▼────────────────────────────┐
                    │ Nostr Relays (untrusted)            │
                    │ Private relay + public inbox relays │
                    └────────────────────────────────────┘
```

---

## 4. Module Reference

### `error.rs`

Defines `ChatError`, the single error type for all fallible operations. Variants carry only display-safe context (no plaintext, no key bytes).

Key constant: `MAX_EVENT_BYTES = 65_536` (64 KiB) — the hard size limit applied before any parsing.

### `identity.rs`

- `IdentityPublicKey` — newtype around `nostr::key::PublicKey`. Safe to log and pass to UI.  
- `IdentityHandle` — wraps `nostr::key::Keys` (secret + public). Custom `Debug` shows only the `npub`. `Display` is **not** implemented (callers must explicitly extract the public half). Marked `ZeroizeOnDrop`.

The secret key never leaves `chat-core` through any public method. Signing and encryption are performed by calling `IdentityHandle::keys()` (crate-private) from `outbound.rs`.

### `types.rs`

Pure data types with no network I/O:

| Type | Description |
|------|-------------|
| `MessageId` | Newtype around `EventId`; opaque inner-message ID for dedup |
| `ChatMessage` | Display-safe decrypted message DTO for the UI |
| `DeliveryState` | Queued / RelayAccepted / Failed |
| `RelayUrl` | Validated `wss://` or `ws://` URL |
| `OutboundTask` | One gift-wrap event + recipient + `is_self_copy` flag |
| `OutboundPlan` | All tasks for one outbound message (includes self-copy) |
| `DeduplicationSet` | `HashSet<MessageId>` for replay prevention |
| `RawInboundEvent` | Raw JSON string before any parsing (passed to `check_size`) |

### `traits.rs`

Interface definitions for injectable components:

| Trait | Description |
|-------|-------------|
| `ChatSigner` | Returns public key; no secret exposure |
| `Keystore` | Generates/loads `ChatSigner` instances |
| `LocalStore` | Persists messages and outbox (implementations encrypt at rest) |
| `RelayTransport` | Publishes events; returns `DeliveryState` |

### `validation.rs`

The inbound security pipeline (see §5). Exposes individual step functions (`check_size`, `parse_event`, `verify_signature`, `check_gift_wrap_kind`, `decrypt_gift_wrap`, `validate_nip17`, `check_dedup`) and the assembled `run_inbound_pipeline` function.

### `outbound.rs`

`plan_outbound(sender, recipients, body)`:

1. Builds one `kind:14` rumor (with all participant `p` tags).
2. Calls `ensure_id()` to pin the rumor's event ID before wrapping.
3. For each recipient: creates a `kind:1059` gift wrap (via `GiftWrapBuilder`).
4. Creates one additional self-copy gift wrap for sent-history recovery.
5. Returns an `OutboundPlan` containing all tasks and the canonical `MessageId`.

---

## 5. Inbound Message Pipeline

```
RawInboundEvent (JSON string from relay)
         │
         ▼
[1] check_size()          ← rejects if > MAX_EVENT_BYTES
         │
         ▼
[2] parse_event()         ← rejects malformed JSON
         │
         ▼
[3] verify_signature()    ← BIP-340 Schnorr, BEFORE decrypt
         │
         ▼
[4] check_gift_wrap_kind()← rejects non-kind:1059
         │
         ▼
[5] decrypt_gift_wrap()   ← NIP-59: verify seal sig,
         │                   verify seal→rumor author match,
         │                   return UnwrappedGift
         ▼
[6] validate_nip17()      ← kind:14, p-tags present,
         │                   expected participants tagged
         ▼
[7] check_dedup()         ← inner EventId not seen before
         │
         ▼
  ValidatedInbound → ChatMessage (display-safe, for UI)
```

Step 3 (signature verification) **must** occur before step 5 (decryption). Reversing this order would allow an attacker to trigger NIP-44 decryption work on arbitrary unsigned ciphertexts.

---

## 6. Outbound Message Flow

```
plan_outbound(sender, [bob, carol], "hello")
         │
         ├─ build kind:14 rumor (p: bob, carol, alice)
         │  └─ ensure_id() → stable MessageId
         │
         ├─ GiftWrapBuilder(bob, rumor).finalize(alice_keys)
         │  └─ OutboundTask { recipient: bob, is_self_copy: false }
         │
         ├─ GiftWrapBuilder(carol, rumor).finalize(alice_keys)
         │  └─ OutboundTask { recipient: carol, is_self_copy: false }
         │
         └─ GiftWrapBuilder(alice, rumor).finalize(alice_keys)
            └─ OutboundTask { recipient: alice, is_self_copy: true }
```

The self-copy allows Alice to recover her sent-message history by subscribing to her own inbox relays, without any server-side sent-message storage.

---

## 7. Key Storage and Lifecycle

```
Keys generated/imported
         │
         ▼
IdentityHandle::generate()
or ::from_secret_hex()
         │
         │  (secret key never returned)
         ▼
Keystore trait implementation
  (platform: iOS Secure Enclave, Android Keystore, macOS Keychain)
         │
         ▼
LocalStore trait implementation
  (messages encrypted at rest; key-wrapping by Keystore)
```

Zeroization: `IdentityHandle` is `ZeroizeOnDrop`. Transient NIP-44 key material inside the `nostr` library is managed by that library.

---

## 8. What `chat-core` Does Not Do

| Concern | Deferred to |
|---------|-------------|
| Network I/O / WebSocket connections | Future `chat-transport` crate using `nostr-sdk` |
| Local database (SQLite, etc.) | Future `chat-store` crate |
| OS keychain integration | Future `chat-keystore-{ios,android,desktop}` crates |
| Flutter/Dart FFI bindings | Future `chat-ffi` crate |
| WASM bindings for web | Future `chat-wasm` crate |
| Push notification hints | Future work (must carry zero content) |
| Encrypted attachments | Future `chat-attachments` crate |
| Group messaging > ~20 participants | Future protocol design (NIP-17 fan-out doesn't scale) |
| Threshold Schnorr / FROST key recovery | Future research; see existing `gennaro-rs` crate |

---

## 9. Cryptography Dependency

All cryptographic primitives are provided by the [`nostr`](https://crates.io/crates/nostr) crate (rust-nostr project):

| Primitive | NIP | Implementation |
|-----------|-----|----------------|
| Identity keys | BIP-340 | `secp256k1` crate via `nostr::key::Keys` |
| Event signing | BIP-340 Schnorr | `secp256k1::schnorr` |
| Message encryption | NIP-44 (ChaCha20-Poly1305 + HKDF-SHA256) | `nostr::nips::nip44` |
| Seal / gift wrap | NIP-59 | `nostr::nips::nip59::GiftWrapBuilder` |
| Relay inbox | NIP-17 | `nostr::nips::nip17` |

**No custom cryptography is implemented in `chat-core`.**

The `nostr` crate dependency is pinned to `=0.45.0-alpha.8` in `Cargo.lock`. Before a production release, the dependency should be updated to a reviewed stable release and `Cargo.lock` committed.

---

## 10. Threshold ECDSA (`gennaro-rs`)

The existing `gennaro-rs` crate implements a threshold ECDSA proof-of-concept (Gennaro et al. protocol, secp256k1, Paillier-based MTA). It is preserved in the workspace but is **not on the chat critical path** for the following reasons:

1. Nostr identity uses **Schnorr/BIP-340**, not ECDSA.
2. The `gennaro-rs` demo prints the aggregated private key to stdout, which is appropriate for academic exploration but not for a production security boundary.
3. A production-ready threshold signer would require threshold **Schnorr/FROST** and independent security review.

Future directions: social key recovery using FROST threshold Schnorr (a separate, opt-in feature not touching `chat-core`'s encryption critical path).
