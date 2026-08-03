/// Typed errors for chat-core.
///
/// All variants expose only display-safe information. No secret key bytes
/// or plaintext message content are ever included in error payloads.
use thiserror::Error;

/// Maximum allowed size for an inbound event, in bytes.
pub const MAX_EVENT_BYTES: usize = 65_536; // 64 KiB

/// The single error type returned by the chat-core library.
#[derive(Debug, Error)]
pub enum ChatError {
    /// The raw inbound event exceeds the configured size limit.
    #[error("event too large: {size} bytes (limit {limit})")]
    EventTooLarge { size: usize, limit: usize },

    /// The event JSON could not be parsed.
    #[error("malformed event: {0}")]
    ParseError(String),

    /// The event's BIP-340 signature failed verification.
    #[error("invalid event signature")]
    InvalidSignature,

    /// The outer gift-wrap event is not of the expected kind.
    #[error("unexpected event kind: expected {expected}, got {got}")]
    UnexpectedKind { expected: u16, got: u16 },

    /// The rumor author does not match the seal signer (potential spoofing).
    #[error("sender public key mismatch between rumor and seal")]
    SenderMismatch,

    /// After unwrapping, the rumor is missing the expected participant pubkeys.
    #[error("participant validation failed: {reason}")]
    ParticipantMismatch { reason: String },

    /// The rumor kind is not the expected NIP-17 private-direct-message kind.
    #[error("unexpected rumor kind: expected {expected}, got {got}")]
    UnexpectedRumorKind { expected: u16, got: u16 },

    /// The inner message ID was already processed (duplicate).
    #[error("duplicate message id")]
    DuplicateMessageId,

    /// An outbound recipient list is empty (cannot build a plan with no recipients).
    #[error("recipient list must not be empty")]
    EmptyRecipients,

    /// NIP-59 unwrapping failed.
    #[error("gift-wrap error: {0}")]
    GiftWrapError(String),

    /// An unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}
