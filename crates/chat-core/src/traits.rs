/// Trait definitions for the major security boundaries.
///
/// These traits define the interfaces between layers of the system.
/// Concrete implementations are deliberately not provided here so that
/// the UI/FFI layer can inject test doubles and so that the keystore
/// implementation can live in a separate, auditable crate.
///
/// # Security invariants
///
/// - No trait method ever returns a secret key, seed phrase, or raw key bytes.
/// - All signing and encryption operations are performed inside the
///   implementation; callers receive only the result (signed event, ciphertext).
use nostr::event::Event;
use nostr::key::PublicKey;

use crate::error::ChatError;
use crate::types::{ChatMessage, DeliveryState, MessageId, OutboundPlan, RelayUrl};

/// A capability-based signer that can sign Nostr events and perform NIP-44
/// encryption/decryption.
///
/// Implementations must never expose the underlying secret key bytes through
/// any public interface.
///
/// In the reference implementation this is backed by `nostr::key::Keys`, but
/// future implementations may delegate to a hardware token, NIP-46 remote
/// signer, or OS keychain.
pub trait ChatSigner: Send + Sync {
    /// Return the public key associated with this signer.
    fn public_key(&self) -> PublicKey;
}

/// Manages identity key lifecycle.
///
/// The keystore creates and stores `ChatSigner` instances. It never returns
/// raw secret key bytes; callers receive only opaque handles.
pub trait Keystore: Send + Sync {
    /// The concrete signer type produced by this keystore.
    type Signer: ChatSigner;

    /// Generate a new random identity and persist it under `label`.
    fn generate_identity(&self, label: &str) -> Result<Self::Signer, ChatError>;

    /// Load an existing identity by `label`.
    fn load_identity(&self, label: &str) -> Result<Self::Signer, ChatError>;
}

/// Persists chat messages and queued outbound events.
///
/// All data stored here should be encrypted at rest by the implementing
/// layer; the trait itself does not mandate an encryption scheme so that
/// different platforms can use native secure storage.
pub trait LocalStore: Send + Sync {
    /// Persist a decrypted inbound message.
    fn store_message(&self, msg: &ChatMessage) -> Result<(), ChatError>;

    /// Retrieve messages, ordered oldest-first.
    fn list_messages(&self) -> Result<Vec<ChatMessage>, ChatError>;

    /// Persist an outbound plan for retry.
    fn enqueue_plan(&self, plan: &OutboundPlan) -> Result<(), ChatError>;

    /// Remove a task from the outbox after relay acceptance.
    fn mark_accepted(&self, message_id: &MessageId) -> Result<(), ChatError>;
}

/// Publishes events to one or more Nostr relays.
///
/// # Relay acceptance is not user delivery
///
/// A successful return from `publish` means only that at least one
/// configured relay has acknowledged the event. It does not guarantee
/// that the recipient's client has retrieved or processed the message.
pub trait RelayTransport: Send + Sync {
    /// Publish `event` to the relay at `relay_url`.
    ///
    /// Returns `Ok(DeliveryState::RelayAccepted)` on relay acceptance.
    fn publish(
        &self,
        relay_url: &RelayUrl,
        event: &Event,
    ) -> Result<DeliveryState, ChatError>;
}
