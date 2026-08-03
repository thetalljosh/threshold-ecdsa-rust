/// Inbound event validation pipeline.
///
/// The pipeline enforces the following ordered security checks before any
/// decryption is attempted:
///
/// 1. **Resource bounds** — reject oversized payloads before parsing.
/// 2. **Parse** — reject malformed JSON.
/// 3. **Signature verification** — reject events with invalid BIP-340
///    Schnorr signatures *before* any NIP-44 decryption is performed.
/// 4. **Kind check** — only accept `kind:1059` gift-wrap events.
/// 5. **Decrypt** — unwrap the gift wrap (NIP-59), verify the seal, and
///    extract the rumor. The `nostr` library verifies the seal signature
///    and checks that the rumor's author matches the seal's author.
/// 6. **NIP-17 participant validation** — after unwrapping, confirm that
///    the rumor is `kind:14` and that the expected participants are tagged.
/// 7. **Deduplication** — reject already-seen inner message IDs.
use nostr::event::{Event, EventId, Kind};
use nostr::key::{Keys, PublicKey};
use nostr::nips::nip01::Nip01Tag;
use nostr::nips::nip19::ToBech32;
use nostr::nips::nip59::UnwrappedGift;

use crate::error::{ChatError, MAX_EVENT_BYTES};
use crate::types::{ChatMessage, DeduplicationSet, MessageId, RawInboundEvent};

// ── Step 1: resource-bound check ────────────────────────────────────────────

/// Reject the raw payload if it exceeds `MAX_EVENT_BYTES`.
///
/// This check must happen *before* any JSON parsing to avoid allocating
/// memory proportional to an attacker-controlled payload size.
pub fn check_size(raw: &RawInboundEvent) -> Result<(), ChatError> {
    let size = raw.0.len();
    if size > MAX_EVENT_BYTES {
        return Err(ChatError::EventTooLarge {
            size,
            limit: MAX_EVENT_BYTES,
        });
    }
    Ok(())
}

// ── Step 2: parse ────────────────────────────────────────────────────────────

/// Parse the JSON into a `nostr::event::Event`.
///
/// Rejects malformed JSON and structurally invalid events.
pub fn parse_event(raw: &RawInboundEvent) -> Result<Event, ChatError> {
    Event::from_json(&raw.0).map_err(|e| ChatError::ParseError(e.to_string()))
}

// ── Step 3: signature verification ──────────────────────────────────────────

/// Verify the BIP-340 Schnorr signature on the outer event.
///
/// This step MUST occur before any decryption attempt. Decrypting an
/// event whose signature has not been verified could allow an attacker to
/// trigger NIP-44 decryption work on arbitrary ciphertext.
pub fn verify_signature(event: &Event) -> Result<(), ChatError> {
    event.verify().map_err(|_| ChatError::InvalidSignature)
}

// ── Step 4: kind check ───────────────────────────────────────────────────────

/// Accept only `kind:1059` (gift wrap) events.
pub fn check_gift_wrap_kind(event: &Event) -> Result<(), ChatError> {
    if event.kind != Kind::GiftWrap {
        return Err(ChatError::UnexpectedKind {
            expected: Kind::GiftWrap.as_u16(),
            got: event.kind.as_u16(),
        });
    }
    Ok(())
}

// ── Step 5: decrypt ──────────────────────────────────────────────────────────

/// Decrypt a gift-wrap event and return the `UnwrappedGift`.
///
/// Internally the `nostr` library:
/// - Decrypts the outer gift wrap to obtain the `kind:13` seal.
/// - Verifies the seal's BIP-340 signature.
/// - Decrypts the seal to obtain the rumor.
/// - Checks that the rumor author matches the seal signer.
///
/// All of these checks are performed by the upstream `nostr` library
/// before control returns here.
pub fn decrypt_gift_wrap(signer: &Keys, event: &Event) -> Result<UnwrappedGift, ChatError> {
    UnwrappedGift::from_gift_wrap(signer, event)
        .map_err(|e| ChatError::GiftWrapError(e.to_string()))
}

// ── Step 6: NIP-17 participant validation ────────────────────────────────────

/// Validate the unwrapped rumor as a NIP-17 private direct message.
///
/// Checks:
/// - Rumor must be `kind:14` (PrivateDirectMessage).
/// - `expected_participants` must all appear as `p` tags in the rumor.
/// - At least one `p` tag must be present.
pub fn validate_nip17(
    gift: &UnwrappedGift,
    expected_participants: &[PublicKey],
) -> Result<(), ChatError> {
    // Kind check
    if gift.rumor.kind != Kind::PrivateDirectMessage {
        return Err(ChatError::UnexpectedRumorKind {
            expected: Kind::PrivateDirectMessage.as_u16(),
            got: gift.rumor.kind.as_u16(),
        });
    }

    // Collect `p` tags from the rumor.
    let tagged = extract_p_tags(&gift.rumor);

    if tagged.is_empty() {
        return Err(ChatError::ParticipantMismatch {
            reason: "rumor has no p-tag recipients".to_string(),
        });
    }

    // Every expected participant must appear in the rumor's p tags.
    for pk in expected_participants {
        if !tagged.contains(pk) {
            return Err(ChatError::ParticipantMismatch {
                reason: format!(
                    "expected participant {} not in rumor p-tags",
                    pk.to_bech32().unwrap_or_default()
                ),
            });
        }
    }

    Ok(())
}

// ── Step 7: deduplication ────────────────────────────────────────────────────

/// Check that the inner message ID has not been seen before.
pub fn check_dedup(
    gift: &UnwrappedGift,
    dedup: &mut DeduplicationSet,
) -> Result<MessageId, ChatError> {
    // Ensure the rumor has an ID (normally set by ensure_id during wrapping).
    let event_id: EventId = gift
        .rumor
        .id
        .ok_or_else(|| ChatError::ParseError("rumor missing event ID".to_string()))?;

    let msg_id = MessageId::from_event_id(event_id);

    if dedup.check_and_insert(&msg_id) {
        return Err(ChatError::DuplicateMessageId);
    }

    Ok(msg_id)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Extract all `p`-tagged public keys from an unsigned event.
pub(crate) fn extract_p_tags(rumor: &nostr::event::UnsignedEvent) -> Vec<PublicKey> {
    rumor
        .tags
        .iter()
        .filter_map(|t| {
            if let Ok(Nip01Tag::PublicKey { public_key, .. }) = Nip01Tag::try_from(t.clone()) {
                Some(public_key)
            } else {
                None
            }
        })
        .collect()
}

// ── Assembled pipeline result ────────────────────────────────────────────────

/// A fully validated inbound message ready for the UI layer.
#[derive(Debug)]
pub struct ValidatedInbound {
    /// The canonical inner message ID.
    pub message_id: MessageId,
    /// The sender's public key (verified against the seal).
    pub sender: PublicKey,
    /// The plain-text message body.
    pub body: String,
    /// The rumor timestamp (seconds since Unix epoch).
    pub timestamp: u64,
    /// Participant public keys from the rumor's `p` tags.
    pub participants: Vec<PublicKey>,
}

impl ValidatedInbound {
    /// Convert to a display-safe [`ChatMessage`] for the UI layer.
    pub fn into_chat_message(self) -> ChatMessage {
        ChatMessage {
            id: self.message_id,
            sender: self.sender,
            body: self.body,
            timestamp: self.timestamp,
            participants: self.participants,
        }
    }
}

/// Run the full inbound validation pipeline.
///
/// Steps: size check → parse → signature verify → kind check →
/// decrypt → NIP-17 validate → dedup.
///
/// The `expected_participants` slice contains the public keys of the known
/// participants in this conversation. Pass an empty slice to skip the
/// participant check (not recommended for production).
pub fn run_inbound_pipeline(
    raw: &RawInboundEvent,
    signer: &Keys,
    expected_participants: &[PublicKey],
    dedup: &mut DeduplicationSet,
) -> Result<ValidatedInbound, ChatError> {
    // 1. Size
    check_size(raw)?;
    // 2. Parse
    let event = parse_event(raw)?;
    // 3. Signature — before any decryption
    verify_signature(&event)?;
    // 4. Kind
    check_gift_wrap_kind(&event)?;
    // 5. Decrypt
    let gift = decrypt_gift_wrap(signer, &event)?;
    // 6. Participant validation
    validate_nip17(&gift, expected_participants)?;
    // 7. Dedup
    let msg_id = check_dedup(&gift, dedup)?;

    let participants = extract_p_tags(&gift.rumor);

    Ok(ValidatedInbound {
        message_id: msg_id,
        sender: gift.sender,
        body: gift.rumor.content.clone(),
        timestamp: gift.rumor.created_at.as_secs(),
        participants,
    })
}
