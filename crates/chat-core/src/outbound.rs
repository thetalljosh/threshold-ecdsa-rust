/// Outbound message planning.
///
/// Builds a per-recipient gift-wrap fan-out for a NIP-17 private message
/// and ensures a self-copy is included for sent-history recovery.
///
/// # NIP-17 per-recipient fan-out
///
/// NIP-17 requires one separate gift wrap per recipient so that each wrap
/// is encrypted to *only* that recipient's public key. Recipients cannot
/// see each other's wraps. A self-copy (encrypted to the sender's own key)
/// is added so the sender can recover their sent messages locally without
/// relying on relays.
///
/// # Relay acknowledgement caveat
///
/// Successful publication of a gift wrap to a relay constitutes relay
/// acceptance, not proof that the recipient has received or read the
/// message.
use nostr::event::{EventBuilder, FinalizeEvent, FinalizeUnsignedEvent, Kind, Tag, UnsignedEvent};
use nostr::key::{Keys, PublicKey};
use nostr::nips::nip59::GiftWrapBuilder;

use crate::error::ChatError;
use crate::identity::IdentityHandle;
use crate::types::{MessageId, OutboundPlan, OutboundTask};

/// Build an outbound [`OutboundPlan`] for a single plain-text message.
///
/// Creates:
/// - One `kind:14` rumor with all participant `p` tags.
/// - For every recipient: a `kind:13` seal + `kind:1059` gift wrap encrypted
///   to that recipient.
/// - One additional self-copy gift wrap encrypted to the sender's own key.
///
/// # Parameters
///
/// - `sender` — the sender's identity handle.
/// - `recipients` — the intended recipients (must not be empty).
/// - `body` — the plain-text message content.
///
/// # Errors
///
/// Returns [`ChatError::EmptyRecipients`] if `recipients` is empty.
pub fn plan_outbound(
    sender: &IdentityHandle,
    recipients: &[PublicKey],
    body: &str,
) -> Result<OutboundPlan, ChatError> {
    if recipients.is_empty() {
        return Err(ChatError::EmptyRecipients);
    }

    let sender_keys: &Keys = sender.keys();
    let sender_pubkey: PublicKey = sender_keys.public_key();

    // Build the rumor once; all recipients share the same event ID.
    // Tag the primary recipient, any additional recipients, and the sender.
    let mut rumor: UnsignedEvent = EventBuilder::new(Kind::PrivateDirectMessage, body)
        .tag(Tag::public_key(recipients[0]))
        .tags(recipients[1..].iter().map(|pk| Tag::public_key(*pk)))
        .tag(Tag::public_key(sender_pubkey))
        .finalize_unsigned(sender_pubkey);

    // Ensure the rumor gets a stable ID (used for dedup and tracking).
    rumor.ensure_id();

    let message_id = MessageId::from_event_id(
        rumor
            .id
            .ok_or_else(|| ChatError::Internal("rumor ID missing after ensure_id".into()))?,
    );

    let mut tasks: Vec<OutboundTask> = Vec::with_capacity(recipients.len() + 1);

    // Per-recipient gift wraps.
    for recipient in recipients {
        let event = GiftWrapBuilder::new(*recipient, rumor.clone())
            .finalize(sender_keys)
            .map_err(|e| ChatError::GiftWrapError(e.to_string()))?;

        tasks.push(OutboundTask {
            event,
            recipient: *recipient,
            is_self_copy: false,
        });
    }

    // Self-copy: gift wrap encrypted to the sender's own public key so that
    // sent-message history is recoverable without trusting relays.
    let self_event = GiftWrapBuilder::new(sender_pubkey, rumor)
        .finalize(sender_keys)
        .map_err(|e| ChatError::GiftWrapError(e.to_string()))?;

    tasks.push(OutboundTask {
        event: self_event,
        recipient: sender_pubkey,
        is_self_copy: true,
    });

    Ok(OutboundPlan { message_id, tasks })
}
