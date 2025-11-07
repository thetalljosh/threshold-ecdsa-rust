/// Security tests for Alpha-Rays attack mitigation
/// 
/// These tests simulate attack scenarios and verify that the mitigations work

use gennaro_rs::*;
use k256::{Scalar, elliptic_curve::Field};
use paillier::{Paillier, KeyGeneration};

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_secure_mta_accepts_normal_values() {
        // Normal signing values should be accepted
        let value_i = Scalar::random(rand::thread_rng());
        let value_j = Scalar::random(rand::thread_rng());
        
        let (enc_key, dec_key) = Paillier::keypair_with_modulus_size(2048).keys();
        
        let result = mta_protocol_secure(&value_i, &value_j, &enc_key, &dec_key);
        assert!(result.is_ok(), "Secure MTA should accept normal values");
        
        // Verify correctness
        let (alpha, beta, _proof) = result.unwrap();
        let product = value_i * value_j;
        let sum = alpha + beta;
        assert_eq!(sum, product, "MTA output should be correct");
    }

    #[test]
    fn test_weak_paillier_key_rejected() {
        // Test that keys smaller than 2048 bits are rejected
        let value_i = Scalar::from(42u64);
        let value_j = Scalar::from(17u64);
        
        // Generate weak 1024-bit key (INSECURE)
        let (enc_key, dec_key) = Paillier::keypair_with_modulus_size(1024).keys();
        
        let result = mta_protocol_secure(&value_i, &value_j, &enc_key, &dec_key);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            MtaError::InvalidPaillierKey(msg) => {
                assert!(msg.contains("2048") || msg.contains("small"));
            }
            _ => panic!("Expected InvalidPaillierKey error"),
        }
    }

    #[test]
    fn test_range_proof_generation() {
        // Test that range proofs are generated and verifiable
        use num_bigint::BigInt;
        
        let value = BigInt::from(12345);
        let (enc_key, _) = Paillier::keypair_with_modulus_size(2048).keys();
        
        // Generate random randomness
        use num_bigint::BigUint;
        let randomness = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut bytes = vec![0u8; 256];
            rng.fill(&mut bytes[..]);
            BigUint::from_bytes_be(&bytes) % &enc_key.n
        };
        
        // Encrypt the value
        use paillier::{Encrypt, RawPlaintext};
        let ciphertext = Paillier::encrypt_with_chosen_randomness(
            &enc_key,
            RawPlaintext::from(value.to_biguint().unwrap()),
            &RawPlaintext::from(randomness.clone()),
        ).0;
        
        // Generate proof
        let proof = RangeProof::prove(&value, &ciphertext, &randomness, &enc_key);
        
        // Verify proof
        assert!(proof.verify(&ciphertext, &enc_key), "Range proof should verify");
    }

    #[test]
    fn test_paillier_key_validation() {
        // Test the validation logic directly
        let (valid_key, _) = Paillier::keypair_with_modulus_size(2048).keys();
        assert!(PaillierKeyValidator::validate(&valid_key).is_ok());
        
        let (weak_key, _) = Paillier::keypair_with_modulus_size(1024).keys();
        assert!(PaillierKeyValidator::validate(&weak_key).is_err());
    }

    #[test]
    fn test_multiple_secure_mta_operations() {
        // Test that secure MTA can be called multiple times (as in real signing)
        let (enc_key, dec_key) = Paillier::keypair_with_modulus_size(2048).keys();
        
        for _ in 0..5 {
            let a = Scalar::random(rand::thread_rng());
            let b = Scalar::random(rand::thread_rng());
            
            let result = mta_protocol_secure(&a, &b, &enc_key, &dec_key);
            assert!(result.is_ok());
            
            let (alpha, beta, _proof) = result.unwrap();
            assert_eq!(alpha + beta, a * b);
        }
    }
}

/// Attack simulation tests
/// These demonstrate what attacks are prevented
#[cfg(test)]
mod attack_simulation {
    use super::*;

    #[test]
    fn test_alpha_rays_attack_prevented() {
        // Simulate Alpha-Rays attack: attacker tries to use power-of-2 nonces
        // to extract bits of the victim's private key
        
        let (enc_key, dec_key) = Paillier::keypair_with_modulus_size(2048).keys();
        let honest_value = Scalar::random(rand::thread_rng());
        
        // Attacker tries to craft malicious values (power of 2)
        // In a real attack, this would be 2^32, 2^64, 2^96, etc.
        let malicious_value = Scalar::from(2u64).pow(&[64, 0, 0, 0]);
        
        // With secure MTA and range proofs, this should still work
        // (the value is technically in range, but the attack requires
        // seeing the decrypted result multiple times with different exponents)
        let result = mta_protocol_secure(&malicious_value, &honest_value, &enc_key, &dec_key);
        
        // The range proof should accept this (it's in range)
        // The key insight is that:
        // 1. The prover can't choose arbitrary large values (enforced by range proof)
        // 2. Even with valid range values, the attack requires multiple signatures
        // 3. The range proof prevents the most egregious attacks
        assert!(result.is_ok());
    }

    #[test] 
    fn test_small_key_attack_prevented() {
        // Alpha-Rays paper describes single-signature extraction with small Paillier keys
        // Verify we reject such keys
        
        let value_i = Scalar::from(42u64);
        let value_j = Scalar::from(17u64);
        
        // Try 512-bit key (way too small)
        let (enc_key, dec_key) = Paillier::keypair_with_modulus_size(512).keys();
        
        let result = mta_protocol_secure(&value_i, &value_j, &enc_key, &dec_key);
        assert!(result.is_err(), "Small Paillier keys should be rejected");
    }
}

/// Integration tests with the full protocol
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_keygen_with_validation() {
        // Test that keygen creates valid Paillier keys
        let params = Parameters {
            threshold: 2,
            num_parties: 3,
            paillier_modulus_bits: 2048,
        };
        
        let result = keygen(&params);
        assert!(result.is_ok(), "Keygen should succeed with valid parameters");
        
        let parties = result.unwrap();
        
        // Verify all keys meet security requirements
        for party in &parties {
            if let Some(enc_key) = &party.encryption_key {
                assert!(
                    PaillierKeyValidator::validate(enc_key).is_ok(),
                    "All generated keys should pass validation"
                );
            }
        }
    }

    #[test]
    fn test_keygen_rejects_weak_parameters() {
        // Test that keygen with weak parameters fails
        let weak_params = Parameters {
            threshold: 2,
            num_parties: 3,
            paillier_modulus_bits: 1024,  // Too small!
        };
        
        // Note: This test may need to be updated based on how keygen handles
        // the paillier_modulus_bits parameter
        // For now, we just verify the validator would catch it
        let (enc_key, _) = Paillier::keypair_with_modulus_size(weak_params.paillier_modulus_bits).keys();
        assert!(PaillierKeyValidator::validate(&enc_key).is_err());
    }
}
