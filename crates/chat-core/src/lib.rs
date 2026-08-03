//! `chat-core` — security-first Nostr NIP-17 private chat library.
//!
//! This library provides:
//!
//! - Typed domain models and opaque identity handles that never expose secret
//!   key bytes through `Debug` or `Display`.
//! - Trait interfaces for the signer, keystore, local store, and relay
//!   transport layers (implementations live in separate crates / the UI layer).
//! - An inbound validation pipeline that enforces resource bounds, signature
//!   verification *before* decryption, NIP-17 participant checks, and
//!   deduplication.
//! - An outbound planner that generates one gift wrap per recipient plus a
//!   mandatory self-copy for sent-history recovery.
//!
//! # Security model
//!
//! See `docs/THREAT_MODEL.md` and `docs/ARCHITECTURE.md` at the repository
//! root for the complete security design.
//!
//! # Cryptography
//!
//! All cryptographic operations are delegated to the [`nostr`] crate
//! (rust-nostr project). No custom cryptography is implemented here.

pub mod error;
pub mod identity;
pub mod outbound;
pub mod traits;
pub mod types;
pub mod validation;

pub use error::ChatError;
pub use identity::{IdentityHandle, IdentityPublicKey};
pub use types::{
    ChatMessage, DeduplicationSet, DeliveryState, MessageId, OutboundPlan, OutboundTask,
    RawInboundEvent, RelayUrl,
};
