/// Educational Module for Threshold Cryptography
/// 
/// This module demonstrates threshold cryptography concepts using SMALL NUMBERS
/// that students can verify by hand or with a calculator.
/// 
/// WARNING: This is for EDUCATIONAL PURPOSES ONLY!
/// Do NOT use this for any real cryptographic application!
/// 
/// Key Simplifications:
/// - Uses small prime modulus (p = 97) instead of 256-bit curve order
/// - Uses simple integer arithmetic instead of elliptic curves
/// - All operations are in modular arithmetic mod p
/// - Numbers are small enough to verify by hand

use std::collections::HashMap;

/// Small prime modulus for educational purposes
/// We use 97 because it's:
/// - A prime number (required for field arithmetic)
/// - Small enough for hand calculation
/// - Large enough to demonstrate concepts
pub const MODULUS: i64 = 97;

/// Generator for our "group" (just an integer in Z_p*)
/// In real ECDSA, this would be the generator point G on the elliptic curve
pub const GENERATOR: i64 = 5;

/// Extended Euclidean Algorithm to find modular inverse
/// Returns: (gcd, x, y) where gcd = ax + by
fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (gcd, x1, y1) = extended_gcd(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;
    (gcd, x, y)
}

/// Calculate modular inverse: a^(-1) mod m
/// Example: mod_inverse(3, 97) = 65 because (3 * 65) mod 97 = 1
fn mod_inverse(a: i64, m: i64) -> i64 {
    let (gcd, x, _) = extended_gcd(a, m);
    assert_eq!(gcd, 1, "Modular inverse doesn't exist");
    ((x % m + m) % m)
}

/// Modular exponentiation: base^exp mod m
/// Example: mod_exp(5, 3, 97) = 28 because 5^3 = 125, 125 mod 97 = 28
fn mod_exp(base: i64, exp: i64, m: i64) -> i64 {
    if exp == 0 {
        return 1;
    }
    let mut result = 1;
    let mut base = base % m;
    let mut exp = exp;
    
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % m;
        }
        exp = exp >> 1;
        base = (base * base) % m;
    }
    result
}

/// Educational representation of a "point" (in real ECDSA, this would be a curve point)
/// Here, we just use g^x mod p to simulate scalar multiplication
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EduPoint {
    pub value: i64,  // Represents g^x mod p
}

impl EduPoint {
    /// Create a point from a scalar: Point = g^scalar mod p
    pub fn from_scalar(scalar: i64) -> Self {
        EduPoint {
            value: mod_exp(GENERATOR, scalar, MODULUS),
        }
    }

    /// "Add" two points (in our simplified model, this is multiplication mod p)
    /// In real ECDSA, this would be elliptic curve point addition
    pub fn add(&self, other: &EduPoint) -> EduPoint {
        EduPoint {
            value: (self.value * other.value) % MODULUS,
        }
    }

    /// Identity element (in our model, 1; in ECDSA, point at infinity)
    pub fn identity() -> Self {
        EduPoint { value: 1 }
    }
}

/// ============================================================================
/// SHAMIR SECRET SHARING (Educational Version)
/// ============================================================================

pub struct EduShamirSecretSharing {
    pub threshold: usize,
    pub num_shares: usize,
}

impl EduShamirSecretSharing {
    /// Create shares of a secret using Shamir's Secret Sharing
    /// 
    /// Example with threshold=2, num_shares=3, secret=42:
    /// 1. Create polynomial f(x) = 42 + a₁x where a₁ is random (say 17)
    /// 2. f(x) = 42 + 17x
    /// 3. Shares: f(1) = 59, f(2) = 76, f(3) = 93
    /// 4. Any 2 shares can reconstruct the secret
    pub fn share(threshold: usize, num_shares: usize, secret: i64) -> (Vec<i64>, Vec<i64>) {
        println!("\n=== SHAMIR SECRET SHARING ===");
        println!("Secret: {}", secret);
        println!("Threshold: {} (need {} shares to reconstruct)", threshold, threshold);
        println!("Total shares: {}\n", num_shares);

        // Create polynomial: f(x) = secret + a₁x + a₂x² + ... + aₜ₋₁x^(t-1)
        let mut coefficients = vec![secret];
        
        println!("Polynomial coefficients:");
        println!("  a₀ (secret) = {}", secret);
        
        // Generate random coefficients (in real crypto, these would be cryptographically random)
        for i in 1..threshold {
            let coef = ((i * 17 + 7) % MODULUS as usize) as i64; // Deterministic for educational clarity
            coefficients.push(coef);
            println!("  a{} (random) = {}", i, coef);
        }

        // Build polynomial string for display
        let mut poly_str = format!("{}", coefficients[0]);
        for (i, &coef) in coefficients.iter().enumerate().skip(1) {
            poly_str.push_str(&format!(" + {}x^{}", coef, i));
        }
        println!("\nPolynomial: f(x) = {}", poly_str);

        // Evaluate polynomial at x = 1, 2, 3, ... to create shares
        let mut shares = Vec::new();
        println!("\nEvaluating polynomial to create shares:");
        
        for x in 1..=num_shares {
            let mut share = 0i64;
            let mut x_power = 1i64;
            
            print!("  f({}) = ", x);
            for (i, &coef) in coefficients.iter().enumerate() {
                if i > 0 {
                    print!(" + ");
                }
                let term = (coef * x_power) % MODULUS;
                print!("{}*{}^{}", coef, x, i);
                share = (share + term) % MODULUS;
                x_power = (x_power * x as i64) % MODULUS;
            }
            share = ((share % MODULUS) + MODULUS) % MODULUS;
            println!(" = {} (mod {})", share, MODULUS);
            shares.push(share);
        }

        let x_coords: Vec<i64> = (1..=num_shares as i64).collect();
        println!("\nShares created: {:?}", shares);
        (x_coords, shares)
    }

    /// Reconstruct secret from threshold shares using Lagrange interpolation
    /// 
    /// Example: Given shares (1, 59) and (2, 76), reconstruct secret at x=0
    /// Using Lagrange: f(0) = y₁*L₁(0) + y₂*L₂(0)
    /// Where L₁(0) = (0-2)/(1-2) = 2 and L₂(0) = (0-1)/(2-1) = -1
    pub fn reconstruct(x_coords: &[i64], shares: &[i64]) -> i64 {
        println!("\n=== SECRET RECONSTRUCTION ===");
        println!("Using {} shares: {:?}", shares.len(), shares);
        println!("At x-coordinates: {:?}\n", x_coords);

        let mut secret = 0i64;

        println!("Lagrange interpolation at x = 0:");
        for i in 0..shares.len() {
            let xi = x_coords[i];
            let yi = shares[i];

            // Calculate Lagrange basis polynomial L_i(0)
            let mut numerator = 1i64;
            let mut denominator = 1i64;

            print!("  L_{}(0) = ", i);
            for j in 0..shares.len() {
                if i != j {
                    let xj = x_coords[j];
                    numerator = (numerator * (0 - xj)) % MODULUS;
                    denominator = (denominator * (xi - xj)) % MODULUS;
                    
                    if j > 0 && j != i {
                        print!(" × ");
                    }
                    print!("(0 - {})/({}  - {})", xj, xi, xj);
                }
            }

            numerator = ((numerator % MODULUS) + MODULUS) % MODULUS;
            denominator = ((denominator % MODULUS) + MODULUS) % MODULUS;
            let denominator_inv = mod_inverse(denominator, MODULUS);
            let lagrange_coef = (numerator * denominator_inv) % MODULUS;

            println!(" = {} (mod {})", lagrange_coef, MODULUS);
            println!("    Contribution: {} × {} = {}", yi, lagrange_coef, (yi * lagrange_coef) % MODULUS);

            secret = (secret + yi * lagrange_coef) % MODULUS;
        }

        secret = ((secret % MODULUS) + MODULUS) % MODULUS;
        println!("\nReconstructed secret: {}\n", secret);
        secret
    }
}

/// ============================================================================
/// FELDMAN VERIFIABLE SECRET SHARING (Educational Version)
/// ============================================================================

pub struct EduFeldmanVSS {
    pub threshold: usize,
    pub num_shares: usize,
    pub commitments: Vec<EduPoint>,  // g^a₀, g^a₁, g^a₂, ...
}

impl EduFeldmanVSS {
    /// Create verifiable shares with commitments
    /// 
    /// The key insight: We publish g^aᵢ for each coefficient aᵢ
    /// This allows verification without revealing the coefficients
    pub fn share(threshold: usize, num_shares: usize, secret: i64) -> (Self, Vec<i64>, Vec<i64>) {
        println!("\n=== FELDMAN VERIFIABLE SECRET SHARING ===");
        println!("Secret: {}", secret);
        
        // Create polynomial coefficients
        let mut coefficients = vec![secret];
        println!("\nPolynomial coefficients:");
        println!("  a₀ (secret) = {}", secret);
        
        for i in 1..threshold {
            let coef = ((i * 17 + 7) % MODULUS as usize) as i64;
            coefficients.push(coef);
            println!("  a{} = {}", i, coef);
        }

        // Create commitments: C_i = g^a_i mod p
        let mut commitments = Vec::new();
        println!("\nCommitments (public values):");
        for (i, &coef) in coefficients.iter().enumerate() {
            let commitment = EduPoint::from_scalar(coef);
            println!("  C{} = {}^{} mod {} = {}", i, GENERATOR, coef, MODULUS, commitment.value);
            commitments.push(commitment);
        }

        // Create shares
        let mut shares = Vec::new();
        let x_coords: Vec<i64> = (1..=num_shares as i64).collect();
        
        println!("\nCreating shares:");
        for &x in &x_coords {
            let mut share = 0i64;
            let mut x_power = 1i64;
            
            for &coef in &coefficients {
                share = (share + coef * x_power) % MODULUS;
                x_power = (x_power * x) % MODULUS;
            }
            share = ((share % MODULUS) + MODULUS) % MODULUS;
            println!("  Share for x={}: {}", x, share);
            shares.push(share);
        }

        let vss = EduFeldmanVSS {
            threshold,
            num_shares,
            commitments,
        };

        (vss, x_coords, shares)
    }

    /// Verify that a share is valid using the public commitments
    /// 
    /// Verification: g^share ?= C₀^(x^0) × C₁^(x^1) × C₂^(x^2) × ...
    /// This works because:
    ///   g^share = g^(a₀ + a₁x + a₂x² + ...)
    ///           = g^a₀ × g^(a₁x) × g^(a₂x²) × ...
    ///           = g^a₀ × (g^a₁)^x × (g^a₂)^x² × ...
    ///           = C₀ × C₁^x × C₂^x² × ...
    pub fn verify_share(&self, x: i64, share: i64) -> bool {
        println!("\n=== VERIFYING SHARE ===");
        println!("Share for x={}: {}", x, share);
        
        // Left side: g^share mod p
        let left = EduPoint::from_scalar(share);
        println!("Left side: {}^{} mod {} = {}", GENERATOR, share, MODULUS, left.value);

        // Right side: C₀ × C₁^x × C₂^x² × ...
        let mut right = EduPoint::identity();
        let mut x_power = 1i64;
        
        println!("Right side:");
        for (i, commitment) in self.commitments.iter().enumerate() {
            let term = EduPoint {
                value: mod_exp(commitment.value, x_power, MODULUS),
            };
            println!("  C{}^({}^{}) = {}^{} = {}", i, x, i, commitment.value, x_power, term.value);
            right = right.add(&term);
            x_power = (x_power * x) % MODULUS;
        }
        
        println!("Combined right side: {}", right.value);
        let valid = left.value == right.value;
        println!("Verification: {} (left == right: {})", if valid { "✓ VALID" } else { "✗ INVALID" }, valid);
        
        valid
    }
}

/// ============================================================================
/// SIMPLIFIED MTA (Educational Version)
/// ============================================================================

/// Educational version of Multiplicative-to-Additive conversion
/// 
/// Goal: Convert multiplicative shares into additive shares
/// Given: Party A has secret 'a', Party B has secret 'b'
/// Want: Shares α and β such that α + β = a × b (mod p)
/// 
/// In the real implementation, this uses Paillier homomorphic encryption.
/// Here, we simulate the concept with simple arithmetic.
pub struct EduMTA;

impl EduMTA {
    /// Simulate MTA protocol
    /// 
    /// Real MTA uses Paillier encryption, but conceptually:
    /// 1. Party A generates random α
    /// 2. Party B computes β = a × b - α
    /// 3. Result: α + β = a × b
    /// 
    /// Note: This simplified version doesn't provide the security guarantees
    /// of real MTA, but demonstrates the mathematical concept
    pub fn convert(a: i64, b: i64) -> (i64, i64) {
        println!("\n=== MTA: MULTIPLICATIVE-TO-ADDITIVE CONVERSION ===");
        println!("Party A's secret: a = {}", a);
        println!("Party B's secret: b = {}", b);
        println!("Goal: Convert a × b into additive shares α + β\n");

        // Compute product
        let product = (a * b) % MODULUS;
        println!("Product: a × b = {} × {} = {} (mod {})", a, b, product, MODULUS);

        // Party A generates random α (simulated for educational purposes)
        let alpha = ((a + b + 13) % MODULUS); // Deterministic for clarity
        println!("\nParty A generates random α = {}", alpha);

        // Party B computes β such that α + β = a × b
        let beta = ((product - alpha) % MODULUS + MODULUS) % MODULUS;
        println!("Party B computes β = (a×b - α) mod p");
        println!("                  β = ({} - {}) mod {}", product, alpha, MODULUS);
        println!("                  β = {}", beta);

        // Verify
        let sum = (alpha + beta) % MODULUS;
        println!("\nVerification:");
        println!("  α + β = {} + {} = {} (mod {})", alpha, beta, sum, MODULUS);
        println!("  a × b = {}", product);
        println!("  Match: {} ✓", sum == product);

        (alpha, beta)
    }

    /// Multi-party MTA for threshold signing
    /// Demonstrates how MTA is used across multiple parties
    pub fn multi_party_convert(values: &[i64]) -> Vec<i64> {
        println!("\n=== MULTI-PARTY MTA ===");
        println!("Party values: {:?}\n", values);

        let n = values.len();
        let mut shares = vec![0i64; n];

        println!("Computing pairwise products:");
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    let (alpha, beta) = Self::convert(values[i], values[j]);
                    println!("  Party {} gets α = {}", i, alpha);
                    println!("  Party {} gets β = {}\n", j, beta);
                    
                    shares[i] = (shares[i] + alpha) % MODULUS;
                    shares[j] = (shares[j] + beta) % MODULUS;
                }
            }
        }

        println!("Final additive shares: {:?}", shares);
        
        // Verify
        let total: i64 = shares.iter().sum();
        let total_mod = ((total % MODULUS) + MODULUS) % MODULUS;
        
        let mut expected = 0i64;
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    expected = (expected + values[i] * values[j]) % MODULUS;
                }
            }
        }
        expected = ((expected % MODULUS) + MODULUS) % MODULUS;
        
        println!("\nVerification:");
        println!("  Sum of shares: {}", total_mod);
        println!("  Expected (sum of all i×j): {}", expected);
        println!("  Match: {} ✓", total_mod == expected);

        shares
    }
}

/// ============================================================================
/// THRESHOLD SIGNING DEMONSTRATION
/// ============================================================================

pub struct EduThresholdSignature;

impl EduThresholdSignature {
    /// Demonstrate threshold signing with small numbers
    /// 
    /// Simplified signature scheme: s = k + c × x (mod p)
    /// Where:
    ///   k = nonce (like 'r' in ECDSA)
    ///   c = challenge/hash (like hash of message)
    ///   x = private key
    pub fn sign(private_key_shares: &[i64], message: &str) {
        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║     EDUCATIONAL THRESHOLD SIGNATURE DEMONSTRATION        ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        
        println!("\nMessage to sign: \"{}\"", message);
        println!("Number of signing parties: {}", private_key_shares.len());
        println!("Private key shares: {:?}\n", private_key_shares);

        // Step 1: Each party generates a nonce
        println!("STEP 1: Generate Nonces");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        let nonces: Vec<i64> = (0..private_key_shares.len())
            .map(|i| ((i as i64 * 23 + 11) % MODULUS))
            .collect();
        
        for (i, &nonce) in nonces.iter().enumerate() {
            println!("  Party {}: k_{} = {}", i, i, nonce);
        }

        // Step 2: Compute challenge (simulated hash)
        println!("\nSTEP 2: Compute Challenge (Hash of Message)");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        let challenge = (message.bytes().map(|b| b as i64).sum::<i64>() % MODULUS);
        println!("  c = hash(\"{}\") = {} (mod {})", message, challenge, MODULUS);

        // Step 3: Use MTA to convert k × x into additive shares
        println!("\nSTEP 3: MTA for k × x Conversion");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        let mta_shares = EduMTA::multi_party_convert(private_key_shares);

        // Step 4: Each party computes partial signature
        println!("\nSTEP 4: Compute Partial Signatures");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        let mut partial_sigs = Vec::new();
        for i in 0..private_key_shares.len() {
            let s_i = (nonces[i] + challenge * mta_shares[i]) % MODULUS;
            let s_i = ((s_i % MODULUS) + MODULUS) % MODULUS;
            println!("  Party {}: s_{} = k_{} + c × (MTA share)", i, i, i);
            println!("           s_{} = {} + {} × {}", i, nonces[i], challenge, mta_shares[i]);
            println!("           s_{} = {} (mod {})", i, s_i, MODULUS);
            partial_sigs.push(s_i);
        }

        // Step 5: Combine partial signatures
        println!("\nSTEP 5: Combine Partial Signatures");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        let signature: i64 = partial_sigs.iter().sum();
        let signature = ((signature % MODULUS) + MODULUS) % MODULUS;
        
        println!("  Combined: s = s_0 + s_1 + ... + s_n");
        println!("  Combined: s = {} (mod {})", signature, MODULUS);

        println!("\n✓ Signature generated successfully!");
        println!("  Final signature: {}", signature);
        println!("  (In real ECDSA, this would be the 's' component of the (r, s) signature pair)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_secret_sharing() {
        let secret = 42;
        let (x_coords, shares) = EduShamirSecretSharing::share(2, 3, secret);
        
        // Reconstruct with first 2 shares
        let reconstructed = EduShamirSecretSharing::reconstruct(&x_coords[0..2], &shares[0..2]);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_feldman_vss() {
        let secret = 42;
        let (vss, x_coords, shares) = EduFeldmanVSS::share(2, 3, secret);
        
        // Verify all shares
        for i in 0..3 {
            assert!(vss.verify_share(x_coords[i], shares[i]));
        }
    }

    #[test]
    fn test_mta() {
        let a = 7;
        let b = 11;
        let (alpha, beta) = EduMTA::convert(a, b);
        
        let sum = (alpha + beta) % MODULUS;
        let product = (a * b) % MODULUS;
        assert_eq!(sum, product);
    }
}
