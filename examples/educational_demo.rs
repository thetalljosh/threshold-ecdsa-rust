/// Educational Examples for Threshold Cryptography
/// 
/// Run this file to see step-by-step demonstrations of:
/// - Shamir Secret Sharing
/// - Feldman Verifiable Secret Sharing  
/// - MTA Protocol
/// - Threshold Signing
/// 
/// All with small numbers you can verify by hand!

mod educational;

use educational::*;

fn print_header(title: &str) {
    println!("\n");
    println!("╔═════════════════════════════════════════════════════════════════╗");
    println!("║ {:^63} ║", title);
    println!("╚═════════════════════════════════════════════════════════════════╝");
}

fn main() {
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                                                                   ║");
    println!("║      THRESHOLD CRYPTOGRAPHY EDUCATIONAL DEMONSTRATION             ║");
    println!("║                                                                   ║");
    println!("║  Learn cryptography with numbers small enough to verify by hand! ║");
    println!("║                                                                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");

    println!("\n📚 KEY CONCEPTS:");
    println!("   • Prime modulus: p = {}", MODULUS);
    println!("   • Generator: g = {}", GENERATOR);
    println!("   • All arithmetic is done modulo {}", MODULUS);
    println!("   • You can verify every calculation with a calculator!");

    // ========================================================================
    // EXAMPLE 1: Shamir Secret Sharing
    // ========================================================================
    print_header("EXAMPLE 1: Shamir Secret Sharing");
    
    println!("\n💡 CONCEPT: Split a secret into shares where any t shares can");
    println!("   reconstruct it, but t-1 shares reveal nothing.\n");

    let secret = 42;
    let (x_coords, shares) = EduShamirSecretSharing::share(2, 3, secret);
    
    println!("\n📝 TRY IT YOURSELF:");
    println!("   Using shares ({}, {}) and ({}, {})", x_coords[0], shares[0], x_coords[1], shares[1]);
    println!("   Calculate: f(0) using Lagrange interpolation");
    println!("   You should get: {}", secret);

    let reconstructed = EduShamirSecretSharing::reconstruct(&x_coords[0..2], &shares[0..2]);
    
    println!("\n✅ SUCCESS: Reconstructed secret = {} (original was {})", 
             reconstructed, secret);

    // ========================================================================
    // EXAMPLE 2: Feldman Verifiable Secret Sharing
    // ========================================================================
    print_header("EXAMPLE 2: Feldman Verifiable Secret Sharing");
    
    println!("\n💡 CONCEPT: Like Shamir SSS, but with PUBLIC COMMITMENTS that");
    println!("   allow anyone to verify shares are valid without seeing the secret.\n");

    let secret2 = 35;
    let (vss, x_coords2, shares2) = EduFeldmanVSS::share(2, 3, secret2);
    
    println!("\n🔍 Now let's verify a share is valid:");
    let is_valid = vss.verify_share(x_coords2[0], shares2[0]);
    
    if is_valid {
        println!("\n✅ Share verification succeeded!");
    }

    println!("\n📝 TRY IT YOURSELF:");
    println!("   Verify share manually:");
    println!("   1. Compute left side: {}^{} mod {}", GENERATOR, shares2[0], MODULUS);
    println!("   2. Compute right side: Product of commitments raised to powers");
    println!("   3. Check if they're equal!");

    // ========================================================================
    // EXAMPLE 3: Simple MTA
    // ========================================================================
    print_header("EXAMPLE 3: Multiplicative-to-Additive (MTA)");
    
    println!("\n💡 CONCEPT: Convert a multiplication (a × b) into addition (α + β)");
    println!("   This is the KEY technique that makes threshold ECDSA secure!\n");

    let a = 7;
    let b = 11;
    let (alpha, beta) = EduMTA::convert(a, b);
    
    println!("\n📝 TRY IT YOURSELF:");
    println!("   Given: a = {}, b = {}", a, b);
    println!("   Compute: ({} × {}) mod {} = {}", a, b, MODULUS, (a * b) % MODULUS);
    println!("   Verify: ({} + {}) mod {} = {}", alpha, beta, MODULUS, (alpha + beta) % MODULUS);
    println!("   Check if they're equal!");

    // ========================================================================
    // EXAMPLE 4: Multi-Party MTA
    // ========================================================================
    print_header("EXAMPLE 4: Multi-Party MTA");
    
    println!("\n💡 CONCEPT: MTA across multiple parties for threshold operations\n");

    let party_values = vec![3, 5, 7];
    let shares = EduMTA::multi_party_convert(&party_values);
    
    println!("\n✅ Each party now has an additive share of all pairwise products!");

    // ========================================================================
    // EXAMPLE 5: Threshold Signature
    // ========================================================================
    print_header("EXAMPLE 5: Threshold Signature (Putting It All Together)");
    
    println!("\n💡 CONCEPT: Multiple parties collaborate to sign a message");
    println!("   without any single party knowing the full private key.\n");

    let message = "Hello Crypto!";
    let private_key_shares = vec![15, 23, 31];  // Shares of the private key
    
    EduThresholdSignature::sign(&private_key_shares, message);

    // ========================================================================
    // INTERACTIVE CHALLENGE
    // ========================================================================
    print_header("🎓 STUDENT CHALLENGE");
    
    println!("\n Try these exercises with a calculator:");
    println!("\n 1. SECRET SHARING:");
    println!("    Create your own 2-of-3 secret sharing for secret = 50");
    println!("    Polynomial: f(x) = 50 + 20x (mod 97)");
    println!("    Calculate: f(1), f(2), f(3)");
    println!("    Reconstruct: Use any 2 shares to get back 50");
    
    println!("\n 2. MTA CONVERSION:");
    println!("    Convert 8 × 9 into additive shares:");
    println!("    Product: (8 × 9) mod 97 = 72");
    println!("    Pick α = 30");
    println!("    Calculate β such that (α + β) mod 97 = 72");
    
    println!("\n 3. VERIFICATION:");
    println!("    Secret: 60, Coefficient: 25");
    println!("    Commitment C₀ = {}^60 mod {}", GENERATOR, MODULUS);
    println!("    Commitment C₁ = {}^25 mod {}", GENERATOR, MODULUS);
    println!("    Share at x=1: s = (60 + 25×1) mod {} = 85", MODULUS);
    println!("    Verify: {}^85 ?= C₀ × C₁^1 (mod {})", GENERATOR, MODULUS);

    println!("\n 4. LAGRANGE INTERPOLATION:");
    println!("    Given points: (1, 59) and (2, 76)");
    println!("    Find f(0) using Lagrange interpolation");
    println!("    L₁(0) = (0-2)/(1-2) = 2");
    println!("    L₂(0) = (0-1)/(2-1) = -1 = 96 (mod 97)");
    println!("    f(0) = 59×2 + 76×96 (mod 97)");
    println!("    What secret do you get?");

    // ========================================================================
    // COMPARISON WITH REAL CRYPTO
    // ========================================================================
    print_header("🔒 EDUCATIONAL vs REAL CRYPTOGRAPHY");
    
    println!("\n This Educational Version:");
    println!("   ✓ Uses small prime p = 97");
    println!("   ✓ Operations in simple modular arithmetic");
    println!("   ✓ Numbers fit on a calculator");
    println!("   ✓ Every step is visible and verifiable");
    println!("   ✗ NOT SECURE - for learning only!");
    
    println!("\n Real ECDSA Implementation:");
    println!("   • Uses 256-bit prime (secp256k1 curve order)");
    println!("   • Operations on elliptic curve points");
    println!("   • Numbers have ~77 decimal digits");
    println!("   • Same mathematical principles!");
    println!("   • Cryptographically secure");

    println!("\n📊 SCALE COMPARISON:");
    println!("   Educational modulus:  97 (2 digits)");
    println!("   Bitcoin/Ethereum:     2^256 ≈ 10^77 (77 digits)");
    println!("   Ratio:                ~10^75 times larger!");

    println!("\n💡 THE KEY INSIGHT:");
    println!("   The MATH is exactly the same, just scaled up!");
    println!("   What you learned here applies to real crypto.");

    // ========================================================================
    // LEARNING RESOURCES
    // ========================================================================
    print_header("📖 NEXT STEPS FOR LEARNING");
    
    println!("\n 1. Verify all calculations above by hand");
    println!(" 2. Modify the examples and run them again");
    println!(" 3. Try different secrets, thresholds, and party counts");
    println!(" 4. Compare to the production code in signing.rs");
    println!(" 5. Read 'Gennaro-Goldfeder Threshold ECDSA' paper");
    
    println!("\n 📚 Recommended Reading:");
    println!("    • 'Applied Cryptography' by Bruce Schneier");
    println!("    • 'Intro to Modern Cryptography' by Katz & Lindell");
    println!("    • Gennaro & Goldfeder (2018) Threshold ECDSA paper");

    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                                                                   ║");
    println!("║                    🎓 HAPPY LEARNING! 🎓                          ║");
    println!("║                                                                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");
}
