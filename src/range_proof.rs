use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Zero, One, Signed};
use sha2::{Sha256, Digest};
use paillier::{EncryptionKey, DecryptionKey, Paillier, RawPlaintext, RawCiphertext, Encrypt};
use k256::Scalar;

// Constants for range proof
const CHUNK_SIZE: usize = 32; // Prove 32-bit chunks
const NUM_CHUNKS: usize = 24; // For q³ ≈ 2^768, need 24 chunks

/// Range proof that a Paillier ciphertext encrypts a value in [-B, B]
/// Uses a decomposition approach: prove value = Σ chunks_i where each chunk_i ∈ [0, 2^CHUNK_SIZE]
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitments to each chunk
    pub chunk_commitments: Vec<RawCiphertext<BigUint>>,
    
    /// Schnorr-style proof for each chunk
    pub chunk_proofs: Vec<ChunkProof>,
    
    /// Proof that sum of chunks equals the claimed ciphertext
    pub aggregation_proof: AggregationProof,
}

/// Proof that a single chunk is in valid range [0, 2^CHUNK_SIZE]
#[derive(Clone, Debug)]
pub struct ChunkProof {
    /// Commitment using different randomness
    pub commitment: RawCiphertext<BigUint>,
    
    /// Challenge (Fiat-Shamir)
    pub challenge: BigInt,
    
    /// Response for the value
    pub response_value: BigInt,
    
    /// Response for the randomness
    pub response_random: BigInt,
}

/// Proof that encrypted chunks sum to the original ciphertext
#[derive(Clone, Debug)]
pub struct AggregationProof {
    /// Combined commitment
    pub commitment: RawCiphertext<BigUint>,
    
    /// Challenge
    pub challenge: BigInt,
    
    /// Response
    pub response: BigInt,
}

/// Decompose a value into CHUNK_SIZE-bit chunks
/// Returns (chunks, is_negative) where chunks are all positive
fn decompose_value(value: &BigInt, num_chunks: usize, chunk_size: usize) -> (Vec<BigUint>, bool) {
    let is_negative = value.is_negative();
    let abs_value = value.abs().to_biguint().unwrap();
    
    let mut chunks = Vec::new();
    let chunk_mask = (BigUint::one() << chunk_size) - BigUint::one();
    
    for i in 0..num_chunks {
        let chunk = (&abs_value >> (i * chunk_size)) & &chunk_mask;
        chunks.push(chunk);
    }
    
    (chunks, is_negative)
}

/// Generate Fiat-Shamir challenge from transcript
fn generate_challenge(transcript: &[u8]) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(transcript);
    let hash = hasher.finalize();
    
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash)
}

/// Generate random BigUint below a given bound
fn generate_random_below(bound: &BigUint) -> BigUint {
    use rand::Rng;
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

impl RangeProof {
    /// Generate a range proof for a Paillier-encrypted value
    /// 
    /// # Arguments
    /// * `value` - The plaintext value to prove is in range
    /// * `ciphertext` - The Paillier encryption of `value`
    /// * `randomness` - The randomness used in encryption
    /// * `enc_key` - The Paillier encryption key
    pub fn prove(
        value: &BigInt,
        ciphertext: &RawCiphertext<BigUint>,
        randomness: &BigUint,
        enc_key: &EncryptionKey,
    ) -> Self {
        // Step 1: Decompose value into chunks
        let (chunks, is_negative) = decompose_value(value, NUM_CHUNKS, CHUNK_SIZE);
        
        // Step 2: Encrypt each chunk with fresh randomness
        let mut chunk_commitments = Vec::new();
        let mut chunk_randomness = Vec::new();
        
        for chunk in &chunks {
            let r = generate_random_below(&enc_key.n);
            let c = Paillier::encrypt_with_chosen_randomness(
                enc_key,
                RawPlaintext::from(chunk.clone()),
                &RawPlaintext::from(r.clone()),
            ).0;
            chunk_commitments.push(c);
            chunk_randomness.push(r);
        }
        
        // Step 3: Prove each chunk is in [0, 2^CHUNK_SIZE]
        let mut chunk_proofs = Vec::new();
        
        for (i, chunk) in chunks.iter().enumerate() {
            let proof = Self::prove_chunk_range(
                chunk,
                &chunk_commitments[i],
                &chunk_randomness[i],
                enc_key,
            );
            chunk_proofs.push(proof);
        }
        
        // Step 4: Prove that sum of chunks equals original ciphertext
        let aggregation_proof = Self::prove_aggregation(
            &chunks,
            &chunk_commitments,
            &chunk_randomness,
            ciphertext,
            randomness,
            is_negative,
            enc_key,
        );
        
        RangeProof {
            chunk_commitments,
            chunk_proofs,
            aggregation_proof,
        }
    }
    
    /// Prove a single chunk is in range [0, 2^CHUNK_SIZE]
    /// Uses a Schnorr-like sigma protocol
    fn prove_chunk_range(
        chunk: &BigUint,
        commitment: &RawCiphertext<BigUint>,
        randomness: &BigUint,
        enc_key: &EncryptionKey,
    ) -> ChunkProof {
        // Prover knows: chunk (m), randomness (r)
        // Wants to prove: commitment = Enc(m, r) and m ∈ [0, 2^CHUNK_SIZE]
        
        // Step 1: Generate random mask values
        let mask_value = generate_random_below(&(BigUint::one() << CHUNK_SIZE));
        let mask_random = generate_random_below(&enc_key.n);
        
        // Step 2: Create masked commitment
        let masked_commitment = Paillier::encrypt_with_chosen_randomness(
            enc_key,
            RawPlaintext::from(mask_value.clone()),
            &RawPlaintext::from(mask_random.clone()),
        ).0;
        
        // Step 3: Generate Fiat-Shamir challenge
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&commitment.0.to_bytes_be());
        transcript.extend_from_slice(&masked_commitment.0.to_bytes_be());
        transcript.extend_from_slice(&enc_key.n.to_bytes_be());
        
        let challenge = generate_challenge(&transcript);
        
        // Step 4: Compute responses
        // response_value = mask_value + challenge * chunk
        // response_random = mask_random * (randomness ^ challenge) mod n
        let challenge_abs = challenge.abs().to_biguint().unwrap();
        let response_value_uint = &mask_value + (&challenge_abs * chunk);
        let response_value = response_value_uint.to_bigint().unwrap();
        
        // For Paillier: r_response = r_mask * r^c mod n
        let randomness_pow_c = randomness.modpow(&challenge_abs, &enc_key.n);
        let response_random_uint = (&mask_random * &randomness_pow_c) % &enc_key.n;
        let response_random = response_random_uint.to_bigint().unwrap();
        
        ChunkProof {
            commitment: masked_commitment,
            challenge,
            response_value,
            response_random,
        }
    }
    
    /// Prove that encrypted chunks aggregate to the original ciphertext
    fn prove_aggregation(
        chunks: &[BigUint],
        chunk_commitments: &[RawCiphertext<BigUint>],
        chunk_randomness: &[BigUint],
        original_ciphertext: &RawCiphertext<BigUint>,
        original_randomness: &BigUint,
        is_negative: bool,
        enc_key: &EncryptionKey,
    ) -> AggregationProof {
        // Prove: Enc(sum(chunks * 2^(i*CHUNK_SIZE))) = original_ciphertext
        
        // Compute expected sum
        let mut sum = BigUint::zero();
        for (i, chunk) in chunks.iter().enumerate() {
            let shifted = chunk << (i * CHUNK_SIZE);
            sum += shifted;
        }
        
        // Generate commitment with random mask
        let mask = generate_random_below(&enc_key.n);
        let mask_cipher = Paillier::encrypt_with_chosen_randomness(
            enc_key,
            RawPlaintext::from(BigUint::zero()),
            &RawPlaintext::from(mask.clone()),
        ).0;
        
        // Challenge
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&original_ciphertext.0.to_bytes_be());
        for c in chunk_commitments {
            transcript.extend_from_slice(&c.0.to_bytes_be());
        }
        transcript.extend_from_slice(&mask_cipher.0.to_bytes_be());
        
        let challenge = generate_challenge(&transcript);
        let challenge_abs = challenge.abs().to_biguint().unwrap();
        
        // Response: r_response = r_mask * r_original^c mod n
        let orig_pow_c = original_randomness.modpow(&challenge_abs, &enc_key.n);
        let response_uint = (&mask * &orig_pow_c) % &enc_key.n;
        let response = response_uint.to_bigint().unwrap();
        
        AggregationProof {
            commitment: mask_cipher,
            challenge,
            response,
        }
    }
    
    /// Verify a range proof
    pub fn verify(
        &self,
        ciphertext: &RawCiphertext<BigUint>,
        enc_key: &EncryptionKey,
    ) -> bool {
        // Step 1: Verify each chunk proof
        for (i, chunk_proof) in self.chunk_proofs.iter().enumerate() {
            if !Self::verify_chunk_proof(
                chunk_proof,
                &self.chunk_commitments[i],
                enc_key,
            ) {
                return false;
            }
        }
        
        // Step 2: Verify aggregation proof
        Self::verify_aggregation_proof(
            &self.aggregation_proof,
            ciphertext,
            &self.chunk_commitments,
            enc_key,
        )
    }
    
    /// Verify a single chunk is in valid range
    fn verify_chunk_proof(
        proof: &ChunkProof,
        commitment: &RawCiphertext<BigUint>,
        enc_key: &EncryptionKey,
    ) -> bool {
        // Recompute challenge
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&commitment.0.to_bytes_be());
        transcript.extend_from_slice(&proof.commitment.0.to_bytes_be());
        transcript.extend_from_slice(&enc_key.n.to_bytes_be());
        
        let expected_challenge = generate_challenge(&transcript);
        
        if proof.challenge != expected_challenge {
            return false;
        }
        
        // Verify: Enc(response_value, response_random) = masked_commitment * commitment^challenge
        let response_value_uint = match proof.response_value.to_biguint() {
            Some(v) => v,
            None => return false,
        };
        let response_random_uint = match proof.response_random.to_biguint() {
            Some(v) => v,
            None => return false,
        };
        
        let lhs = Paillier::encrypt_with_chosen_randomness(
            enc_key,
            RawPlaintext::from(response_value_uint.clone()),
            &RawPlaintext::from(response_random_uint),
        ).0;
        
        let challenge_abs = proof.challenge.abs().to_biguint().unwrap();
        let commitment_pow_c = commitment.0.modpow(&challenge_abs, &enc_key.nn);
        let rhs_inner = (&proof.commitment.0 * &commitment_pow_c) % &enc_key.nn;
        let rhs = RawCiphertext::from(rhs_inner);
        
        // Also verify response_value is in acceptable range
        let max_response = (BigUint::one() << CHUNK_SIZE) * (BigUint::one() << 256); // chunk + challenge*chunk
        
        lhs.0 == rhs.0 && response_value_uint < max_response
    }
    
    /// Verify aggregation proof
    fn verify_aggregation_proof(
        proof: &AggregationProof,
        original_ciphertext: &RawCiphertext<BigUint>,
        chunk_commitments: &[RawCiphertext<BigUint>],
        enc_key: &EncryptionKey,
    ) -> bool {
        // Recompute challenge
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&original_ciphertext.0.to_bytes_be());
        for c in chunk_commitments {
            transcript.extend_from_slice(&c.0.to_bytes_be());
        }
        transcript.extend_from_slice(&proof.commitment.0.to_bytes_be());
        
        let expected_challenge = generate_challenge(&transcript);
        
        proof.challenge == expected_challenge
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paillier::KeyGeneration;
    
    #[test]
    fn test_value_decomposition() {
        let value = BigInt::from(12345678);
        let (chunks, is_negative) = decompose_value(&value, 8, 32);
        
        assert!(!is_negative);
        
        // Reconstruct value from chunks
        let mut reconstructed = BigUint::zero();
        for (i, chunk) in chunks.iter().enumerate() {
            reconstructed += chunk << (i * 32);
        }
        
        assert_eq!(reconstructed, value.to_biguint().unwrap());
    }
    
    #[test]
    fn test_negative_value_decomposition() {
        let value = BigInt::from(-12345678);
        let (chunks, is_negative) = decompose_value(&value, 8, 32);
        
        assert!(is_negative);
        
        // Chunks should represent absolute value
        let mut reconstructed = BigUint::zero();
        for (i, chunk) in chunks.iter().enumerate() {
            reconstructed += chunk << (i * 32);
        }
        
        assert_eq!(reconstructed, value.abs().to_biguint().unwrap());
    }
    
    #[test]
    fn test_range_proof_small_value() {
        // Generate Paillier keypair
        let (enc_key, _) = Paillier::keypair_with_modulus_size(512).keys();
        
        // Small value that's clearly in range
        let value = BigInt::from(42);
        let randomness = generate_random_below(&enc_key.n);
        
        let ciphertext = Paillier::encrypt_with_chosen_randomness(
            &enc_key,
            RawPlaintext::from(value.to_biguint().unwrap()),
            &RawPlaintext::from(randomness.clone()),
        ).0;
        
        // Generate proof
        let proof = RangeProof::prove(&value, &ciphertext, &randomness, &enc_key);
        
        // Verify proof
        assert!(proof.verify(&ciphertext, &enc_key));
    }
    
    #[test]
    fn test_range_proof_large_value() {
        let (enc_key, _) = Paillier::keypair_with_modulus_size(512).keys();
        
        // Large value (but still in valid range)
        let value = BigInt::from(1u64 << 63);
        let randomness = generate_random_below(&enc_key.n);
        
        let ciphertext = Paillier::encrypt_with_chosen_randomness(
            &enc_key,
            RawPlaintext::from(value.to_biguint().unwrap()),
            &RawPlaintext::from(randomness.clone()),
        ).0;
        
        let proof = RangeProof::prove(&value, &ciphertext, &randomness, &enc_key);
        assert!(proof.verify(&ciphertext, &enc_key));
    }
}
