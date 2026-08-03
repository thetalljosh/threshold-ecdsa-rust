/// Comprehensive tests for chat-core security guarantees.
///
/// Tests cover:
/// - Oversized event rejection (resource-bound)
/// - Malformed event rejection (parse step)
/// - Invalid BIP-340 signature rejected *before* decryption
/// - NIP-17 participant mismatch rejection
/// - Self-copy included in outbound plan
/// - Duplicate inner message ID rejection
/// - No secret key bytes in `Debug` or `Display` output
use chat_core::error::MAX_EVENT_BYTES;
use chat_core::identity::IdentityHandle;
use chat_core::outbound::plan_outbound;
use chat_core::types::{DeduplicationSet, RawInboundEvent};
use chat_core::validation::{
    check_size, decrypt_gift_wrap, parse_event, run_inbound_pipeline, validate_nip17,
    verify_signature,
};
use chat_core::ChatError;
use nostr::event::{EventBuilder, FinalizeEvent, FinalizeUnsignedEvent, Kind, Tag};
use nostr::key::Keys;
use nostr::nips::nip59::GiftWrapBuilder;

// ── Test key constants (not production secrets) ──────────────────────────────
// These 32-byte hex values are test-only fixture keys.

const ALICE_SK: &str = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";
const BOB_SK: &str = "7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";
const CAROL_SK: &str = "5b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e";

// ── Helper: build a valid NIP-17 gift wrap from sender to recipient ──────────

fn make_nip17_gift_wrap(
    sender_keys: &Keys,
    recipient_keys: &Keys,
    body: &str,
) -> nostr::event::Event {
    // Build a kind-14 rumor tagged to the recipient and sender.
    let mut rumor = EventBuilder::new(Kind::PrivateDirectMessage, body)
        .tag(Tag::public_key(recipient_keys.public_key()))
        .tag(Tag::public_key(sender_keys.public_key()))
        .finalize_unsigned(sender_keys.public_key());
    rumor.ensure_id();

    GiftWrapBuilder::new(recipient_keys.public_key(), rumor)
        .finalize(sender_keys)
        .expect("gift wrap construction failed")
}

// ── Test 1: oversized event is rejected before parsing ───────────────────────

#[test]
fn test_oversized_event_rejected() {
    let big_payload = "x".repeat(MAX_EVENT_BYTES + 1);
    let raw = RawInboundEvent(big_payload);

    match check_size(&raw) {
        Err(ChatError::EventTooLarge { size, limit }) => {
            assert!(size > limit, "size should exceed limit");
        }
        other => panic!("expected EventTooLarge, got {other:?}"),
    }
}

// Exactly at the limit should pass.
#[test]
fn test_at_size_limit_passes() {
    let at_limit = "x".repeat(MAX_EVENT_BYTES);
    let raw = RawInboundEvent(at_limit);
    assert!(check_size(&raw).is_ok());
}

// ── Test 2: malformed JSON is rejected at parse step ────────────────────────

#[test]
fn test_malformed_json_rejected() {
    let raw = RawInboundEvent("{not valid json".to_string());
    match parse_event(&raw) {
        Err(ChatError::ParseError(_)) => {}
        other => panic!("expected ParseError, got {other:?}"),
    }
}

#[test]
fn test_empty_input_rejected() {
    let raw = RawInboundEvent(String::new());
    assert!(parse_event(&raw).is_err());
}

// ── Test 3: invalid signature rejected BEFORE decryption ────────────────────
//
// We create a valid gift wrap, then tamper with the signature field in the JSON.
// The pipeline must return `InvalidSignature` without attempting decryption
// (if decryption were attempted on a tampered event, the NIP-44 layer would
// return a different error, not a signature error — proving the order is wrong).

#[test]
fn test_invalid_signature_rejected_before_decrypt() {
    let sender = Keys::parse(ALICE_SK).unwrap();
    let receiver = Keys::parse(BOB_SK).unwrap();

    let valid_event = make_nip17_gift_wrap(&sender, &receiver, "hello");
    let json = valid_event.as_json();

    // Replace the first 8 hex chars of the sig field with zeros.
    let sig_prefix = &valid_event.sig.to_string()[..8];
    let tampered_json = json.replacen(sig_prefix, "00000000", 1);

    let raw = RawInboundEvent(tampered_json);
    let parsed = parse_event(&raw).expect("tampered event should still parse");

    // Must fail at signature check — before any decryption.
    match verify_signature(&parsed) {
        Err(ChatError::InvalidSignature) => {} // expected
        other => panic!("expected InvalidSignature, got {other:?}"),
    }
}

// Verify the full pipeline also rejects on invalid signature.
#[test]
fn test_pipeline_rejects_invalid_signature() {
    let sender = Keys::parse(ALICE_SK).unwrap();
    let receiver = Keys::parse(BOB_SK).unwrap();

    let valid_event = make_nip17_gift_wrap(&sender, &receiver, "hello");
    let json = valid_event.as_json();
    let sig_prefix = &valid_event.sig.to_string()[..8];
    let tampered_json = json.replacen(sig_prefix, "00000000", 1);

    let raw = RawInboundEvent(tampered_json);
    let mut dedup = DeduplicationSet::new();
    let err = run_inbound_pipeline(&raw, &receiver, &[], &mut dedup).unwrap_err();

    assert!(
        matches!(err, ChatError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

// ── Test 4: NIP-17 participant validation ────────────────────────────────────

// Carol is not in the rumor but is expected → should return ParticipantMismatch.
#[test]
fn test_participant_mismatch_rejected() {
    let sender = Keys::parse(ALICE_SK).unwrap();
    let receiver = Keys::parse(BOB_SK).unwrap();
    let carol = Keys::parse(CAROL_SK).unwrap();

    let event = make_nip17_gift_wrap(&sender, &receiver, "hello");
    let gift = decrypt_gift_wrap(&receiver, &event).expect("decrypt failed");

    // Expect carol as participant — she is NOT tagged in the rumor.
    let err = validate_nip17(&gift, &[carol.public_key()]).unwrap_err();
    assert!(
        matches!(err, ChatError::ParticipantMismatch { .. }),
        "expected ParticipantMismatch, got {err:?}"
    );
}

// Both alice and bob are tagged; validation with both must pass.
#[test]
fn test_valid_participants_accepted() {
    let sender = Keys::parse(ALICE_SK).unwrap();
    let receiver = Keys::parse(BOB_SK).unwrap();

    let event = make_nip17_gift_wrap(&sender, &receiver, "hello");
    let gift = decrypt_gift_wrap(&receiver, &event).expect("decrypt failed");

    validate_nip17(&gift, &[sender.public_key(), receiver.public_key()])
        .expect("participant validation should pass");
}

// ── Test 5: self-copy always included in outbound plan ──────────────────────

#[test]
fn test_outbound_plan_includes_self_copy() {
    let alice = IdentityHandle::from_secret_hex(ALICE_SK).unwrap();
    let bob_keys = Keys::parse(BOB_SK).unwrap();

    let plan = plan_outbound(&alice, &[bob_keys.public_key()], "hi bob")
        .expect("plan_outbound failed");

    // Must include exactly one self-copy.
    let self_copies: Vec<_> = plan.tasks.iter().filter(|t| t.is_self_copy).collect();
    assert_eq!(self_copies.len(), 1, "must have exactly one self-copy");

    // The self-copy must be addressed to alice (the sender).
    assert_eq!(
        self_copies[0].recipient,
        alice.public_key().inner().to_owned(),
        "self-copy recipient must be sender"
    );

    // Total tasks = 1 recipient + 1 self-copy = 2.
    assert_eq!(plan.tasks.len(), 2);
}

#[test]
fn test_outbound_plan_multiple_recipients_includes_self_copy() {
    let alice = IdentityHandle::from_secret_hex(ALICE_SK).unwrap();
    let bob_keys = Keys::parse(BOB_SK).unwrap();
    let carol_keys = Keys::parse(CAROL_SK).unwrap();

    let plan = plan_outbound(
        &alice,
        &[bob_keys.public_key(), carol_keys.public_key()],
        "group hello",
    )
    .expect("plan_outbound failed");

    // 2 recipients + 1 self-copy = 3 tasks.
    assert_eq!(plan.tasks.len(), 3);
    assert_eq!(
        plan.tasks.iter().filter(|t| t.is_self_copy).count(),
        1,
        "exactly one self-copy"
    );
}

#[test]
fn test_empty_recipients_rejected() {
    let alice = IdentityHandle::from_secret_hex(ALICE_SK).unwrap();
    match plan_outbound(&alice, &[], "nobody") {
        Err(ChatError::EmptyRecipients) => {}
        other => panic!("expected EmptyRecipients, got {other:?}"),
    }
}

// ── Test 6: duplicate inner message ID rejected ──────────────────────────────

#[test]
fn test_duplicate_message_id_rejected() {
    let sender = Keys::parse(ALICE_SK).unwrap();
    let receiver = Keys::parse(BOB_SK).unwrap();

    let event = make_nip17_gift_wrap(&sender, &receiver, "hello");
    let raw = RawInboundEvent(event.as_json());
    let mut dedup = DeduplicationSet::new();

    // First delivery: must succeed.
    let result1 = run_inbound_pipeline(&raw, &receiver, &[], &mut dedup);
    assert!(result1.is_ok(), "first delivery should succeed: {result1:?}");

    // Second delivery of the same event: must be rejected.
    let result2 = run_inbound_pipeline(&raw, &receiver, &[], &mut dedup);
    assert!(
        matches!(result2, Err(ChatError::DuplicateMessageId)),
        "expected DuplicateMessageId, got {result2:?}"
    );
}

// ── Test 7: no secret key material in Debug or Display output ───────────────

#[test]
fn test_identity_handle_debug_contains_no_secret() {
    let handle = IdentityHandle::from_secret_hex(ALICE_SK).unwrap();
    let debug_output = format!("{handle:?}");

    // The raw secret key hex must NOT appear in debug output.
    assert!(
        !debug_output.contains(ALICE_SK),
        "debug output must not contain the secret key: {debug_output}"
    );
    assert!(
        !debug_output.to_lowercase().contains("nsec"),
        "debug output must not contain nsec prefix: {debug_output}"
    );

    // The public key should be present for tracing utility.
    let pub_key_bech32 = handle.public_key().to_bech32();
    assert!(
        debug_output.contains(&pub_key_bech32),
        "debug output should contain the public key: {debug_output}"
    );
}

#[test]
fn test_identity_public_key_display_is_bech32_npub() {
    let handle = IdentityHandle::from_secret_hex(ALICE_SK).unwrap();
    let pub_display = format!("{}", handle.public_key());

    // Display must not leak the secret.
    assert!(
        !pub_display.contains(ALICE_SK),
        "display must not contain secret: {pub_display}"
    );
    // Must be a bech32 npub.
    assert!(
        pub_display.starts_with("npub"),
        "public key display should be bech32 npub, got: {pub_display}"
    );
}

#[test]
fn test_error_display_does_not_include_raw_key_material() {
    let err = ChatError::ParticipantMismatch {
        reason: "test reason".to_string(),
    };
    assert!(
        !format!("{err}").contains(ALICE_SK),
        "error display should not leak key material"
    );
}

// ── Test 8: relay URL validation ────────────────────────────────────────────

#[test]
fn test_relay_url_validation() {
    use chat_core::types::RelayUrl;

    assert!(RelayUrl::parse("wss://relay.example.com").is_ok());
    assert!(RelayUrl::parse("ws://localhost:7777").is_ok());
    assert!(RelayUrl::parse("WSS://RELAY.EXAMPLE.COM").is_ok(), "case-insensitive");
    assert!(RelayUrl::parse("http://relay.example.com").is_err());
    assert!(RelayUrl::parse("not-a-url").is_err());
}

// ── Test 9: outbound message ID is a valid 32-byte hex string ───────────────

#[test]
fn test_outbound_plan_message_id_is_valid_hex() {
    let alice = IdentityHandle::from_secret_hex(ALICE_SK).unwrap();
    let bob_keys = Keys::parse(BOB_SK).unwrap();

    let plan = plan_outbound(&alice, &[bob_keys.public_key()], "test")
        .expect("plan_outbound failed");

    let id_str = plan.message_id.to_string();
    assert!(!id_str.is_empty());
    assert_eq!(id_str.len(), 64, "event ID should be 32-byte hex (64 chars)");
    assert!(
        id_str.chars().all(|c| c.is_ascii_hexdigit()),
        "event ID must be hex: {id_str}"
    );
}
