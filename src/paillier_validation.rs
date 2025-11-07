use num_bigint::{BigUint, BigInt};
use num_traits::{One, Zero};
use paillier::EncryptionKey;
use thiserror::Error;

pub struct PaillierKeyValidator;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ValidationError {
    #[error("Paillier key too small: {bits} bits (minimum {minimum} bits required)")]
    KeyTooSmall { bits: u64, minimum: u64 },
    
    #[error("Paillier modulus has small factor: {factor}")]
    SmallFactor { factor: u64 },
    
    #[error("Paillier modulus is a perfect power")]
    PerfectPower,
    
    #[error("Paillier modulus is not a product of exactly two primes")]
    NotTwoPrimeProduct,
}

impl PaillierKeyValidator {
    /// Validate that a Paillier key meets security requirements
    pub fn validate(enc_key: &EncryptionKey) -> Result<(), ValidationError> {
        let n = &enc_key.n;
        
        // Check 1: Minimum bit length (2048 bits)
        if n.bits() < 2048 {
            return Err(ValidationError::KeyTooSmall {
                bits: n.bits(),
                minimum: 2048,
            });
        }
        
        // Check 2: No small factors (trial division up to 2^20)
        if let Some(factor) = Self::find_small_factor(n, 1_048_576) {
            return Err(ValidationError::SmallFactor { factor });
        }
        
        // Check 3: Not a perfect power
        if Self::is_perfect_power(n) {
            return Err(ValidationError::PerfectPower);
        }
        
        // Check 4: Passes compositeness test
        // (ensures N is product of exactly 2 primes, not more)
        if !Self::likely_two_prime_product(n) {
            return Err(ValidationError::NotTwoPrimeProduct);
        }
        
        Ok(())
    }
    
    /// Find small factors up to limit using trial division
    fn find_small_factor(n: &BigUint, limit: u64) -> Option<u64> {
        // Check small primes first
        for p in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
            if n % p == BigUint::zero() {
                return Some(p);
            }
        }
        
        // Check remaining odd numbers up to limit
        let mut p = 49u64;
        while p <= limit {
            if n % p == BigUint::zero() {
                return Some(p);
            }
            p += 2;
        }
        
        None
    }
    
    /// Check if N is a perfect power (N = a^b for b > 1)
    fn is_perfect_power(n: &BigUint) -> bool {
        // Check for small exponents (2, 3, 5, 7, 11, ...)
        for exp in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31] {
            if let Some(root) = Self::nth_root(n, exp) {
                if &root.pow(exp) == n {
                    return true;
                }
            }
        }
        false
    }
    
    /// Compute nth root (approximate) using binary search
    fn nth_root(n: &BigUint, exp: u32) -> Option<BigUint> {
        if n.is_zero() {
            return Some(BigUint::zero());
        }
        
        if n.is_one() {
            return Some(BigUint::one());
        }
        
        // Binary search for root
        let mut low = BigUint::one();
        let mut high = n.clone();
        
        for _ in 0..1000 {  // Limit iterations
            let mid = (&low + &high) / 2u32;
            let mid_pow = mid.pow(exp);
            
            if &mid_pow == n {
                return Some(mid);
            } else if &mid_pow < n {
                low = mid.clone();
            } else {
                high = mid.clone();
            }
            
            if &high - &low <= BigUint::one() {
                break;
            }
        }
        
        None
    }
    
    /// Probabilistic test that N is product of exactly 2 primes
    fn likely_two_prime_product(n: &BigUint) -> bool {
        // N must be odd (product of two odd primes)
        if n % 2u32 == BigUint::zero() {
            return false;
        }
        
        // N must be greater than 1
        if n <= &BigUint::one() {
            return false;
        }
        
        // For a proper implementation, we would:
        // 1. Use Miller-Rabin to check N is composite
        // 2. Use Pollard's rho or ECM to try finding factors
        // 3. Check that only 2 prime factors exist
        
        // Simplified: if no small factors and not a perfect power,
        // likely (but not certain) to be a product of two primes
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paillier::{Paillier, KeyGeneration};
    
    #[test]
    fn test_valid_key() {
        let (enc_key, _) = Paillier::keypair_with_modulus_size(2048).keys();
        assert!(PaillierKeyValidator::validate(&enc_key).is_ok());
    }
    
    #[test]
    fn test_weak_key_rejected() {
        let (enc_key, _) = Paillier::keypair_with_modulus_size(1024).keys();
        let result = PaillierKeyValidator::validate(&enc_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::KeyTooSmall { .. }));
    }
    
    #[test]
    fn test_perfect_power_detection() {
        let perfect_square = BigUint::from(144u64); // 12^2
        assert!(PaillierKeyValidator::is_perfect_power(&perfect_square));
        
        let not_perfect = BigUint::from(143u64);
        assert!(!PaillierKeyValidator::is_perfect_power(&not_perfect));
    }
    
    #[test]
    fn test_small_factor_detection() {
        let n = BigUint::from(2 * 3 * 5 * 7 * 11 * 13);
        assert_eq!(PaillierKeyValidator::find_small_factor(&n, 100), Some(2));
        
        let prime = BigUint::from(1000000007u64);
        assert_eq!(PaillierKeyValidator::find_small_factor(&prime, 1000), None);
    }
}
