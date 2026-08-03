/// Core domain types.
///
/// All types here are display-safe; none contain secret key bytes or
/// unencrypted message content beyond what is explicitly for display.
use nostr::event::{Event, EventId};
use nostr::key::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Opaque inner-message ID (the event ID of the decrypted NIP-17 rumor).
///
/// Used for deduplication; safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub(crate) EventId);

impl MessageId {
    pub(crate) fn from_event_id(id: EventId) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A display-safe, decrypted chat message handed to the UI layer.
///
/// Never contains private keys or unprocessed ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Inner event ID of the decrypted rumor (for dedup / display).
    pub id: MessageId,
    /// Sender's public key.
    pub sender: PublicKey,
    /// Plain-text message body.
    pub body: String,
    /// Unix timestamp of the rumor (not the outer gift-wrap timestamp,
    /// which is intentionally randomized by NIP-59).
    pub timestamp: u64,
    /// All participant public keys declared in the rumor.
    pub participants: Vec<PublicKey>,
}

/// Delivery state for an outbound message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    /// Waiting to be published to a relay.
    Queued,
    /// Accepted by at least one relay (relay acceptance, not user delivery).
    RelayAccepted,
    /// All configured relays have rejected or timed out.
    Failed,
}

/// A validated relay URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayUrl(pub String);

impl RelayUrl {
    /// Validate and create a `RelayUrl`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let lower = s.to_lowercase();
        if lower.starts_with("wss://") || lower.starts_with("ws://") {
            Ok(Self(s.to_string()))
        } else {
            Err(format!("relay URL must start with wss:// or ws://: {s}"))
        }
    }
}

/// A per-recipient outbound publish task.
#[derive(Debug)]
pub struct OutboundTask {
    /// The gift-wrapped event to publish to this recipient's inbox relays.
    pub event: Event,
    /// Recipient whose inbox relays should receive this event.
    pub recipient: PublicKey,
    /// Whether this task is the sender's own self-copy (for sent-history recovery).
    pub is_self_copy: bool,
}

/// The complete outbound plan for one chat message.
///
/// Contains one [`OutboundTask`] per recipient (including the sender's
/// own self-copy) along with the canonical inner message ID.
#[derive(Debug)]
pub struct OutboundPlan {
    /// The inner event ID of the rumor (for deduplication / tracking).
    pub message_id: MessageId,
    /// Per-recipient tasks. Guaranteed to include exactly one entry where
    /// `is_self_copy == true`.
    pub tasks: Vec<OutboundTask>,
}

impl OutboundPlan {
    /// Returns the self-copy task, if present (always present by construction).
    pub fn self_copy(&self) -> Option<&OutboundTask> {
        self.tasks.iter().find(|t| t.is_self_copy)
    }
}

/// A set of seen inner message IDs used for deduplication.
#[derive(Debug, Default)]
pub struct DeduplicationSet {
    seen: HashSet<MessageId>,
}

impl DeduplicationSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `id` has been seen before; inserts and returns `false` otherwise.
    pub fn check_and_insert(&mut self, id: &MessageId) -> bool {
        if self.seen.contains(id) {
            true
        } else {
            self.seen.insert(id.clone());
            false
        }
    }

    /// Returns `true` if the given ID has already been seen.
    pub fn contains(&self, id: &MessageId) -> bool {
        self.seen.contains(id)
    }
}

/// A raw, unprocessed inbound event (bytes from the relay wire).
///
/// Holds the JSON string before any parsing or decryption. Size is checked
/// against [`crate::error::MAX_EVENT_BYTES`] before further processing.
#[derive(Debug)]
pub struct RawInboundEvent(pub String);
