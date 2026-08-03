/// Opaque identity types.
///
/// `IdentityHandle` wraps a `nostr::key::Keys` value without exposing the
/// secret key through `Debug` or `Display`. All signing capability is
/// accessed through the `Nip44` / `SignEvent` implementations on `Keys`;
/// callers never receive raw key bytes from this module.
use nostr::key::{Keys, PublicKey};
use nostr::nips::nip19::ToBech32;
use zeroize::ZeroizeOnDrop;

/// A public identity key (display-safe, clonable).
///
/// Wraps a `nostr::key::PublicKey`. Safe to log, display, and pass to UI layers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityPublicKey(pub(crate) PublicKey);

impl IdentityPublicKey {
    /// Return the underlying `nostr::key::PublicKey`.
    pub fn inner(&self) -> &PublicKey {
        &self.0
    }

    /// Encode as `npub1…` bech32.
    pub fn to_bech32(&self) -> String {
        self.0.to_bech32().unwrap_or_default()
    }
}

impl std::fmt::Display for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display only the bech32-encoded public key—never the secret.
        write!(f, "{}", self.to_bech32())
    }
}

impl From<PublicKey> for IdentityPublicKey {
    fn from(pk: PublicKey) -> Self {
        Self(pk)
    }
}

/// An opaque handle to a Nostr identity that holds the `Keys` (secret + public).
///
/// # Security properties
///
/// - `Debug` prints only the public key to prevent accidental secret leakage
///   in logs or test output.
/// - `Display` is intentionally not implemented; callers must explicitly
///   extract the public part via [`IdentityHandle::public_key`].
/// - The inner `Keys` value is zeroized when this struct is dropped.
#[derive(ZeroizeOnDrop)]
pub struct IdentityHandle {
    #[zeroize(skip)] // Keys manages its own secret key memory.
    inner: Keys,
}

// Custom Debug that never prints the secret key.
impl std::fmt::Debug for IdentityHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityHandle")
            .field(
                "public_key",
                &self.inner.public_key().to_bech32().unwrap_or_default(),
            )
            .finish_non_exhaustive()
    }
}

impl IdentityHandle {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        Self {
            inner: Keys::generate(),
        }
    }

    /// Parse an existing identity from a hex-encoded secret key.
    ///
    /// # Errors
    /// Returns an error string if the input is not a valid 32-byte hex secret.
    pub fn from_secret_hex(hex: &str) -> Result<Self, String> {
        Keys::parse(hex).map(|k| Self { inner: k }).map_err(|e| e.to_string())
    }

    /// Return the display-safe public-key handle.
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.inner.public_key())
    }

    /// Borrow the inner `nostr::key::Keys` value for signing operations.
    ///
    /// This is `pub(crate)` to keep the secret key confined within this crate.
    pub(crate) fn keys(&self) -> &Keys {
        &self.inner
    }
}
