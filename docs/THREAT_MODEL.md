# Threat Model

> **Status:** Draft v0.1 — covers the `chat-core` library and the immediate deployment context.  
> **Scope:** NIP-17 private direct messaging over Nostr relays. Excludes frontend, mobile push, and attachment encryption.

---

## 1. Protected Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Nostr identity secret key (`nsec`) | Critical | Device keystore / encrypted local store |
| Decrypted message plaintext | High | Memory only (never persisted unencrypted) |
| Contact list and social graph | Medium | Local encrypted store |
| Message metadata (who talks to whom, when) | Medium | Partially observable by relays |
| Relay authentication credentials | Medium | Device keystore |

---

## 2. Attacker Capabilities

### 2.1 Malicious or Compromised Relay

A relay operated by an adversary can:

- **Observe ciphertext, timing, and sizes** of all published events.
- **Retain all gift-wrap events** indefinitely, even after a client sends delete requests (NIP-09 deletion is advisory, not cryptographic).
- **Selectively withhold** events to specific recipients (censorship / DoS).
- **Replay** old gift-wrap events to trigger decryption attempts.
- **Correlate** sender and recipient public keys with IP addresses and connection timing.
- **Inject** arbitrary events — but injected events must have valid BIP-340 signatures, so forging events under a known public key is computationally infeasible.

**Mitigations in `chat-core`:**

- The outer gift-wrap signature is verified **before** any NIP-44 decryption. An injected event with an invalid signature is rejected at step 3 of the pipeline with no decryption work.
- Duplicate inner message IDs are deduplicated by the inbound pipeline, preventing replay attacks from triggering state changes more than once.
- Payload size is bounded at the intake point (`MAX_EVENT_BYTES = 64 KiB`) before any parsing occurs.

### 2.2 Network Observer (Passive TLS)

A passive observer on the network path (ISP, CDN, VPN exit) with TLS keys can see:

- IP addresses of client and relay.
- Connection timing.
- Encrypted TLS payload sizes (with some granularity).

**Note:** `chat-core` does not implement a transport layer. The calling application must use WSS (TLS) for all relay connections. NIP-59 randomises event timestamps (up to ±2 days) to hinder time-correlation attacks; NIP-44 pads ciphertexts to power-of-two lengths to hinder size-analysis attacks.

### 2.3 Compromised UI / FFI Layer

The UI layer (Flutter, web, CLI) is considered partially untrusted:

- It may pass malformed commands or oversized inputs.
- It may be compromised by a supply-chain attack or XSS (for web UIs).
- It must never receive a private key or raw NIP-44 key material.

**Mitigations in `chat-core`:**

- All signing and encryption is performed inside `chat-core` using opaque key handles (`IdentityHandle`). The FFI surface exposes only public keys, signed events, and display-safe DTOs.
- `IdentityHandle` deliberately does not implement `Display`. `Debug` shows only the `npub` public key, never the secret.
- Errors are typed (`ChatError`) and contain no plaintext message content or key material.

### 2.4 Stolen Local Database or Device

If the device is stolen or the local message store is exfiltrated:

- An attacker with the device but not the unlock PIN cannot access plaintext messages if the local store uses OS-level encrypted storage (e.g., iOS Secure Enclave, Android Keystore, macOS Keychain).
- An attacker with the unlock PIN can access all stored plaintext messages and, depending on keystore implementation, the identity key.

**Mitigations:**

- `chat-core` defines `LocalStore` as a trait; the implementation is expected to use platform-native encrypted storage.
- `chat-core` itself never writes unencrypted message content to disk.
- The `IdentityHandle` is `ZeroizeOnDrop` to reduce the window during which the secret key is in memory.

### 2.5 Malformed or Crafted Events

An attacker (or buggy relay) can send:

- Events with valid signatures but unexpected kinds.
- Gift wraps that decrypt to a rumor with a mismatched sender pubkey (spoofing attempt).
- Gift wraps with no recipient `p` tags.
- Events whose decrypted rumor is not `kind:14`.

**Mitigations in `chat-core`:**

- The inbound pipeline enforces ordered checks. See Section 4.
- NIP-59 `UnwrappedGift::from_gift_wrap` (upstream `nostr` library) verifies that the rumor author matches the seal signer, preventing impersonation via a malformed seal.
- `validate_nip17` checks kind, at least one `p` tag, and that all expected participants are present.

### 2.6 DoS and Spam

Relays can deliver an unbounded number of events:

- Large events waste client memory and CPU.
- High event volume can overwhelm the decryption pipeline.

**Mitigations in `chat-core`:**

- `check_size` rejects events larger than `MAX_EVENT_BYTES` before any memory allocation for parsing.
- `DeduplicationSet` prevents repeated decryption of the same inner event.
- Rate limiting and spam filtering are the responsibility of the relay and the calling application (not `chat-core`).

### 2.7 Key Compromise

If an identity key (`nsec`) is compromised:

- **All stored messages** encrypted to that key can be decrypted by the attacker (past messages are not forward-secret).
- **Future messages** can be sent in the victim's name until the key is rotated and contacts notified.

**Explicit non-mitigations (by design):**

NIP-44 does **not** provide forward secrecy or post-compromise security. There is no Signal-style Double Ratchet or Diffie-Hellman ratchet in this protocol. This is a known and documented limitation of the current NIP-17/NIP-44 design.

Mitigations available:

- Keep identity keys in hardware-backed keystores (Secure Enclave / Keystore) where private key extraction is prevented at the hardware level.
- Support key rotation via a NIP-17 "key-update" message and out-of-band contact re-verification.
- Future: consider FROST threshold Schnorr for social key recovery (separate from `chat-core`).

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────┐
│  UI / FFI (untrusted)               │
│  - passes display-safe DTOs only    │
│  - never holds nsec or NIP-44 key  │
└─────────────┬───────────────────────┘
              │  narrow typed API (ChatError, ChatMessage, OutboundPlan)
┌─────────────▼───────────────────────┐
│  chat-core (trusted)                │
│  - owns signing & encryption        │
│  - enforces all validation steps    │
│  - zeroizes transient secrets       │
└──────┬────────────────┬─────────────┘
       │                │
┌──────▼──────┐  ┌──────▼──────────────┐
│  Keystore   │  │  LocalStore         │
│  (trusted)  │  │  (impl-dependent)   │
│  OS keychain│  │  encrypted at rest  │
└─────────────┘  └──────────────────────┘
                          │
              ┌───────────▼───────────┐
              │  Relay Transport      │
              │  (semi-trusted, WSS)  │
              │  NIP-42 auth required │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │  Nostr Relays         │
              │  (untrusted)          │
              └───────────────────────┘
```

---

## 4. Inbound Pipeline Security Order

The following order is **non-negotiable**. Any reordering introduces vulnerabilities:

1. **Size check** — before any memory allocation for parsing.
2. **Parse** — before any cryptographic work.
3. **Signature verification** — BIP-340 Schnorr on the outer `kind:1059` event, **before NIP-44 decryption**. This prevents an attacker from triggering decryption work on arbitrary ciphertext.
4. **Kind check** — only `kind:1059` proceeds.
5. **Decrypt** — NIP-59 unwrap, seal signature verification (upstream library), seal→rumor author check.
6. **NIP-17 validation** — kind:14, at least one `p` tag, expected participants present.
7. **Deduplication** — inner event ID checked against the seen set.

---

## 5. Relay Metadata Limitations

Even with end-to-end encryption, relays can observe:

- **Sender and recipient public keys** (the outer gift wrap's `p` tag is the recipient's `npub`).
- **Connection IP address and timing**.
- **Ciphertext sizes** (NIP-44 pads to power-of-two but doesn't fully hide sizes).
- **Event publication patterns** (when you are online, how frequently you send).

NIP-59 randomises the `created_at` timestamp by up to ±2 days to reduce time-correlation, but does not eliminate it.

For high-risk communications, Nostr should not be used as a substitute for metadata-resistant protocols (e.g., Signal).

---

## 6. Identity Verification

Nostr public keys (`npub`) are self-sovereign. There is no Certificate Authority or phone-number binding.

Recommended verification procedures:

1. **Out-of-band fingerprint comparison**: display the first 16 characters of the `npub` in the UI and verify with the contact via a separate channel (voice, in-person, Signal).
2. **NIP-05 DNS verification**: optionally bind a `user@domain` handle to the `npub`; this establishes identity but is only as trustworthy as the DNS operator.
3. **Key signing / trust graph**: future work.

---

## 7. NIP-42 Relay Authentication

For private friend-group relays, NIP-42 authentication should be enforced:

- Only authenticated users can publish to the relay.
- Only the `p`-tagged recipient (after authentication) can read gift wraps addressed to them.

This prevents unauthenticated enumeration of recipient inboxes and reduces spam.

---

## 8. Safe Logging Rules

- **Never log** `nsec`, raw NIP-44 key bytes, NIP-44 ciphertext, or decrypted message plaintext.
- **Safe to log**: `npub`, event IDs, relay URLs, error messages (typed `ChatError` variants).
- `IdentityHandle` and `IdentityPublicKey` implement `Debug` to show only the `npub`.
- Log levels: use `DEBUG`/`TRACE` for relay connection state; `INFO` for delivery state transitions; `WARN`/`ERROR` for validation failures.
- Strip all `DEBUG`/`TRACE` log lines from production builds if they could inadvertently include message content.

---

## 9. Explicit Non-Goals

- **Forward secrecy**: NIP-44 does not provide it. Stored messages are exposed if the long-term key is compromised.
- **Post-compromise security**: No ratchet mechanism is implemented.
- **Anonymity at the network layer**: IP addresses are visible to relays. Use Tor or a VPN at the network layer if required.
- **Large-group messaging**: NIP-17 fan-out scales poorly beyond ~20 participants. Group messaging is a future-work item requiring a different protocol design.
- **Attachments**: Encrypted file transfer is deferred to a future crate.
- **Push notifications**: Deferred; any push hint must contain zero message content.
