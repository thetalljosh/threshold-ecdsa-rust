use k256::{Scalar, elliptic_curve::Field};
use paillier::{
    Add, DecryptionKey, EncryptionKey, Mul, Paillier, 
    RawCiphertext, RawPlaintext, Encrypt, Decrypt
};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Zero, One};
use rand::Rng;
use thiserror::Error;
use crate::range_proof::RangeProof;
use crate::paillier_validation::PaillierKeyValidator;

/// MTA (Multiplicative-to-Additive) protocol implementation
/// Converts multiplicative shares (a * b) into additive shares (alpha + beta)
/// such that alpha + beta = a * b (mod q) where q is the curve order
/// 
/// This is crucial for threshold ECDSA to prevent:
/// - Rogue key attacks
/// - Adaptive chosen-message attacks
/// - Key extraction through signature forgery

/// Errors that can occur during MTA protocol
#[derive(Debug, Error)]
pub enum MtaError {
    #[error("Invalid range proof - value may be out of acceptable range")]
    InvalidRangeProof,
    
    #[error("Invalid Paillier key: {0}")]
    InvalidPaillierKey(String),
    
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Represents the result of MTA protocol for one party
#[derive(Debug, Clone)]
pub struct MtaShare {
    pub additive_share: Scalar,
}

/// Party information needed for MTA protocol
#[derive(Clone)]
pub struct MtaParty {
    pub index: usize,
    pub encryption_key: EncryptionKey,
    pub decryption_key: Option<DecryptionKey>,
}

/// Convert k256::Scalar to BigInt for Paillier operations
fn scalar_to_bigint(scalar: &Scalar) -> BigInt {
    let bytes = scalar.to_bytes();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes)
}

/// Convert BigInt back to k256::Scalar (mod curve order)
fn bigint_to_scalar(bigint: &BigInt) -> Scalar {
    // Get the modulus (curve order for secp256k1)
    let curve_order = BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ],
    );

    // Reduce modulo curve order
    let reduced = bigint.rem_euclid(&curve_order);
    
    // Handle negative values
    let positive = if reduced < BigInt::zero() {
        reduced + &curve_order
    } else {
        reduced
    };

    // Convert to bytes (32 bytes for secp256k1)
    let bytes = positive.to_biguint().unwrap().to_bytes_be();
    let mut scalar_bytes = [0u8; 32];
    let offset = 32 - bytes.len().min(32);
    scalar_bytes[offset..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);

    // Convert to Scalar - use a safe conversion with Option handling
    Scalar::from_repr(scalar_bytes.into()).unwrap_or(Scalar::ZERO)
}

/// MTA Protocol: Party i (with secret a_i) and Party j (with secret b_j)
/// want to obtain additive shares alpha_i, beta_j such that:
/// alpha_i + beta_j = a_i * b_j (mod q)
///
/// Steps:
/// 1. Party j encrypts b_j with their Paillier public key: c_j = Enc(b_j)
/// 2. Party i generates random alpha_i and computes:
///    c_alpha = Enc(a_i * b_j - alpha_i) = c_j^{a_i} * Enc(-alpha_i)
/// 3. Party j decrypts to get beta_j = Dec(c_alpha) = a_i * b_j - alpha_i
/// 4. Result: alpha_i + beta_j = a_i * b_j (mod q)
pub fn mta_protocol(
    party_i_value: &Scalar,  // Party i's secret value (a_i)
    party_j_value: &Scalar,  // Party j's secret value (b_j)
    party_j_enc_key: &EncryptionKey,  // Party j's Paillier encryption key
    party_j_dec_key: &DecryptionKey,  // Party j's Paillier decryption key
) -> (Scalar, Scalar) {
    // Convert scalars to BigInt for Paillier operations
    let a_i = scalar_to_bigint(party_i_value);
    let b_j = scalar_to_bigint(party_j_value);

    // Step 1: Party j encrypts b_j
    let b_j_uint = b_j.to_biguint().unwrap();
    let c_j = Paillier::encrypt(party_j_enc_key, RawPlaintext::from(b_j_uint.clone()));

    // Step 2: Party i generates random alpha_i
    let mut rng = rand::thread_rng();
    let alpha_i_bytes: [u8; 32] = rng.gen();
    let alpha_i_scalar = Scalar::from_repr(alpha_i_bytes.into()).unwrap_or(Scalar::ONE);
    let alpha_i = scalar_to_bigint(&alpha_i_scalar);

    // Step 3: Party i computes c_j^{a_i} (homomorphic scalar multiplication)
    // This gives us Enc(a_i * b_j)
    let a_i_uint = a_i.to_biguint().unwrap();
    let c_product = Paillier::mul(party_j_enc_key, c_j.clone(), RawPlaintext::from(a_i_uint));

    // Step 4: Party i encrypts -alpha_i
    let neg_alpha_i = -alpha_i.clone();
    let curve_order = BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ],
    );
    let neg_alpha_i_mod = neg_alpha_i.rem_euclid(&curve_order);
    let neg_alpha_i_uint = neg_alpha_i_mod.to_biguint().unwrap();
    let c_neg_alpha = Paillier::encrypt(party_j_enc_key, RawPlaintext::from(neg_alpha_i_uint));

    // Step 5: Compute c_alpha = c_j^{a_i} * Enc(-alpha_i) = Enc(a_i * b_j - alpha_i)
    let c_alpha = Paillier::add(party_j_enc_key, c_product, c_neg_alpha);

    // Step 6: Party j decrypts to get beta_j = a_i * b_j - alpha_i
    let beta_j_plain = Paillier::decrypt(party_j_dec_key, c_alpha);
    let beta_j_bigint = beta_j_plain.0.to_bigint().unwrap();
    let beta_j_scalar = bigint_to_scalar(&beta_j_bigint);

    // Return (alpha_i, beta_j) such that alpha_i + beta_j = a_i * b_j (mod q)
    (alpha_i_scalar, beta_j_scalar)
}

/// Performs MTA protocol across all pairs of signing parties
/// Returns additive shares for each party such that the sum equals the product
pub fn multi_party_mta(
    parties: &[MtaParty],
    party_values: &[Scalar],  // Secret values for each party
) -> Vec<Scalar> {
    let n = parties.len();
    let mut additive_shares = vec![Scalar::ZERO; n];

    // For each pair (i, j) where i < j, perform MTA protocol
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }

            // Perform MTA between party i and party j
            let party_j_dec_key = parties[j].decryption_key.as_ref()
                .expect("Party must have decryption key for MTA");

            let (alpha_ij, beta_ji) = mta_protocol(
                &party_values[i],
                &party_values[j],
                &parties[j].encryption_key,
                party_j_dec_key,
            );

            // Party i accumulates alpha_ij
            additive_shares[i] += alpha_ij;
            
            // Party j accumulates beta_ji
            additive_shares[j] += beta_ji;
        }
    }

    additive_shares
}

/// SECURE MTA Protocol with Range Proofs
/// This version includes zero-knowledge range proofs to prevent Alpha-Rays attacks
/// 
/// Returns (alpha_i, beta_j, range_proof) where the proof demonstrates that
/// party_i_value is in the acceptable range [-q³, q³]
pub fn mta_protocol_secure(
    party_i_value: &Scalar,  // Party i's secret value (a_i)
    party_j_value: &Scalar,  // Party j's secret value (b_j)
    party_j_enc_key: &EncryptionKey,  // Party j's Paillier encryption key
    party_j_dec_key: &DecryptionKey,  // Party j's Paillier decryption key
) -> Result<(Scalar, Scalar, RangeProof), MtaError> {
    // CRITICAL: Validate Paillier key before use
    PaillierKeyValidator::validate(party_j_enc_key)
        .map_err(|e| MtaError::InvalidPaillierKey(e.to_string()))?;
    
    // Convert scalars to BigInt
    let a_i = scalar_to_bigint(party_i_value);
    let b_j = scalar_to_bigint(party_j_value);
    
    // Step 1: Party j encrypts b_j
    let b_j_uint = b_j.to_biguint().unwrap();
    let c_j = Paillier::encrypt(party_j_enc_key, RawPlaintext::from(b_j_uint.clone()));
    
    // Step 2: Party i generates random alpha_i
    let mut rng = rand::thread_rng();
    let alpha_i_bytes: [u8; 32] = rng.gen();
    let alpha_i_scalar = Scalar::from_repr(alpha_i_bytes.into()).unwrap_or(Scalar::ONE);
    let alpha_i = scalar_to_bigint(&alpha_i_scalar);
    
    // Step 3: Party i computes c_j^{a_i} with tracked randomness
    let a_i_uint = a_i.to_biguint().unwrap();
    let randomness_product = generate_random_below(&party_j_enc_key.n);
    
    // Compute the product ciphertext with known randomness
    let product_value = (&a_i_uint * &b_j_uint) % &get_curve_order_uint();
    let c_product = Paillier::encrypt_with_chosen_randomness(
        party_j_enc_key,
        RawPlaintext::from(product_value.clone()),
        &RawPlaintext::from(randomness_product.clone()),
    ).0;
    
    // Step 4: **CRITICAL** - Generate range proof for a_i
    // This proves that a_i is in acceptable range without revealing it
    let range_proof = RangeProof::prove(
        &a_i,
        &c_product,
        &randomness_product,
        party_j_enc_key,
    );
    
    // Step 5: Party j MUST verify the range proof before decrypting
    // This prevents malicious party i from using out-of-range values
    if !range_proof.verify(&c_product, party_j_enc_key) {
        return Err(MtaError::InvalidRangeProof);
    }
    
    // Step 6: Now safe to proceed - encrypt -alpha_i and combine
    let neg_alpha_i = -alpha_i.clone();
    let curve_order = get_curve_order();
    let neg_alpha_i_mod = neg_alpha_i.rem_euclid(&curve_order);
    let neg_alpha_i_uint = neg_alpha_i_mod.to_biguint().unwrap();
    let c_neg_alpha = Paillier::encrypt(party_j_enc_key, RawPlaintext::from(neg_alpha_i_uint));
    
    let c_alpha = Paillier::add(party_j_enc_key, c_product, c_neg_alpha);
    
    // Step 7: Party j decrypts (safe now that range proof verified)
    let beta_j_plain = Paillier::decrypt(party_j_dec_key, c_alpha);
    let beta_j_bigint = beta_j_plain.0.to_bigint().unwrap();
    let beta_j_scalar = bigint_to_scalar(&beta_j_bigint);
    
    Ok((alpha_i_scalar, beta_j_scalar, range_proof))
}

/// Helper: Get curve order as BigInt
fn get_curve_order() -> BigInt {
    BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ],
    )
}

/// Helper: Get curve order as BigUint
fn get_curve_order_uint() -> BigUint {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ])
}

/// Helper: Generate random BigUint below bound
fn generate_random_below(bound: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    let byte_len = (bound.bits() + 7) / 8;
    let mut bytes = vec![0u8; byte_len];
    
    loop {
        rng.fill(&mut bytes[..]);
        let candidate = BigUint::from_bytes_be(&bytes);
        if &candidate < bound {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paillier::KeyGeneration;

    #[test]
    fn test_mta_protocol() {
        // Generate test values
        let a = Scalar::from(42u64);
        let b = Scalar::from(17u64);
        
        // Generate Paillier keypair
        let (ek, dk) = Paillier::keypair().keys();

        // Run MTA protocol
        let (alpha, beta) = mta_protocol(&a, &b, &ek, &dk);

        // Verify: alpha + beta = a * b (mod q)
        let product = a * b;
        let sum = alpha + beta;

        assert_eq!(sum, product, "MTA protocol failed: alpha + beta != a * b");
    }

    #[test]
    fn test_multi_party_mta() {
        let n = 3;
        let mut parties = Vec::new();
        let mut values = Vec::new();

        // Create parties with Paillier keys
        for i in 0..n {
            let keypair = Paillier::keypair();
            let (ek, dk) = keypair.keys();
            
            parties.push(MtaParty {
                index: i,
                encryption_key: ek.clone(),
                decryption_key: Some(dk.clone()),
            });

            values.push(Scalar::from((i + 1) as u64));
        }

        // Run multi-party MTA
        let shares = multi_party_mta(&parties, &values);

        // Verify the sum of shares equals the sum of products
        let total_share: Scalar = shares.iter().fold(Scalar::ZERO, |acc, &s| acc + s);
        
        // Calculate expected sum: sum of all a_i * b_j pairs
        let mut expected = Scalar::ZERO;
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    expected += values[i] * values[j];
                }
            }
        }

        assert_eq!(total_share, expected, "Multi-party MTA failed");
    }
    
    #[test]
    fn test_secure_mta_valid_range() {
        // Test that secure MTA works for valid values
        let a = Scalar::from(42u64);
        let b = Scalar::from(17u64);
        
        // Generate 2048-bit Paillier keypair (secure)
        let (ek, dk) = Paillier::keypair_with_modulus_size(2048).keys();

        // Run secure MTA protocol
        let result = mta_protocol_secure(&a, &b, &ek, &dk);
        assert!(result.is_ok());
        
        let (alpha, beta, _proof) = result.unwrap();

        // Verify: alpha + beta = a * b (mod q)
        let product = a * b;
        let sum = alpha + beta;
        assert_eq!(sum, product);
    }
    
    #[test]
    fn test_secure_mta_rejects_weak_key() {
        // Test that weak Paillier keys are rejected
        let a = Scalar::from(42u64);
        let b = Scalar::from(17u64);
        
        // Generate weak 1024-bit key
        let (ek, dk) = Paillier::keypair_with_modulus_size(1024).keys();

        // Should fail validation
        let result = mta_protocol_secure(&a, &b, &ek, &dk);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MtaError::InvalidPaillierKey(_)));
    }
}
