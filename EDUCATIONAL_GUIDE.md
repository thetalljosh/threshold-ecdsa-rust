# Educational Guide: Threshold Cryptography with Small Numbers

## Overview

This educational module demonstrates threshold cryptography concepts using **small numbers** that students can verify by hand or with a basic calculator. This makes the mathematical principles transparent and accessible.

## Why Small Numbers?

### The Problem with Real Cryptography
Real ECDSA uses numbers like:
```
Curve order (secp256k1): 
115792089237316195423570985008687907852837564279074904382605163141518161494337

That's 78 digits! 
```

Students can't:
- Verify calculations by hand
- Understand what's happening at each step
- Debug when something goes wrong
- Build intuition for the math

### Our Solution
We use **modulus p = 97** (a prime number):
- Small enough for hand calculation (2 digits)
- Large enough to demonstrate concepts
- Same mathematical principles as real crypto
- **10^75 times smaller** than real ECDSA, but the math is identical!

## How to Run

### Quick Start
```bash
# Run the educational demonstration
cargo run --example educational_demo

# Run the tests
cargo test educational
```

### What You'll See
The program demonstrates:
1. **Shamir Secret Sharing** - Split secrets into shares
2. **Feldman VSS** - Verifiable secret sharing with public commitments
3. **MTA Protocol** - Convert multiplication to addition
4. **Threshold Signatures** - Collaborative signing

All with step-by-step explanations and numbers you can verify!

## Educational Concepts

### 1. Shamir Secret Sharing (SSS)

**Goal**: Split a secret into n shares where any t shares can reconstruct it.

**Example with small numbers:**
```
Secret: s = 42
Threshold: t = 2
Shares: n = 3
Modulus: p = 97

Step 1: Create polynomial f(x) = 42 + 17x (mod 97)
  - a₀ = 42 (the secret)
  - a₁ = 17 (random coefficient)

Step 2: Evaluate at x = 1, 2, 3
  f(1) = 42 + 17×1 = 59 (mod 97)
  f(2) = 42 + 17×2 = 76 (mod 97)  
  f(3) = 42 + 17×3 = 93 (mod 97)

Shares: (1, 59), (2, 76), (3, 93)

Step 3: Reconstruct from any 2 shares using Lagrange interpolation
  Using (1, 59) and (2, 76):
  
  L₁(0) = (0-2)/(1-2) = 2 (mod 97)
  L₂(0) = (0-1)/(2-1) = -1 = 96 (mod 97)
  
  f(0) = 59×2 + 76×96 (mod 97)
       = 118 + 7296 (mod 97)
       = 7414 (mod 97)
       = 42 ✓

You can verify this with a calculator!
```

**Try it yourself:**
```rust
use gennaro_rs::educational::*;

let secret = 42;
let (x_coords, shares) = EduShamirSecretSharing::share(2, 3, secret);
let reconstructed = EduShamirSecretSharing::reconstruct(&x_coords[0..2], &shares[0..2]);

assert_eq!(reconstructed, secret);
```

### 2. Feldman Verifiable Secret Sharing (VSS)

**Goal**: Like SSS, but with public commitments that allow verification.

**Example with small numbers:**
```
Secret: s = 42
Polynomial: f(x) = 42 + 17x (mod 97)
Generator: g = 5

Step 1: Create public commitments
  C₀ = g^(a₀) = 5^42 mod 97 = 85
  C₁ = g^(a₁) = 5^17 mod 97 = 56

Step 2: Create shares (same as SSS)
  Share for x=1: s₁ = f(1) = 42 + 17×1 = 59

Step 3: ANYONE can verify the share (without knowing the secret!)
  We need to check if: g^(share) = C₀ × C₁^x (mod 97)
  
   Working example:
    Secret: s = 5
    Polynomial: f(x) = 5 + 3x (mod 97)
    Generator: g = 2
    
    Commitments:
      C₀ = 2^5 mod 97 = 32
      C₁ = 2^3 mod 97 = 8
    
    Share at x=1: s₁ = 5 + 3×1 = 8
    
    Verification:
      Left:  2^8 mod 97 = 256 mod 97 = 62
      Right: 32 × 8 mod 97 = 256 mod 97 = 62 ✓
    
    They match! The share is valid.
```
```

**The Magic**: 
```
g^(share) = g^(a₀ + a₁×x + a₂×x² + ...)
          = g^(a₀) × g^(a₁×x) × g^(a₂×x²) × ...
          = g^(a₀) × (g^a₁)^x × (g^a₂)^x² × ...
          = C₀ × C₁^x × C₂^x² × ...

This works because exponentiation distributes over addition!
```

**Try it yourself:**
```rust
let secret = 42;
let (vss, x_coords, shares) = EduFeldmanVSS::share(2, 3, secret);

// Verify first share
assert!(vss.verify_share(x_coords[0], shares[0]));
```

### 3. MTA (Multiplicative-to-Additive)

**Goal**: Convert a × b into α + β (where α + β = a × b).

**Why this matters**: This is the KEY security feature of threshold ECDSA!

**Example with small numbers:**
```
Party A's secret: a = 7
Party B's secret: b = 11
Modulus: p = 97

Goal: Convert multiplication into addition

Step 1: Compute product
  a × b = 7 × 11 = 77 (mod 97)

Step 2: Party A generates random α
  α = 30 (random)

Step 3: Party B computes β
  β = (a×b - α) mod p
  β = (77 - 30) mod 97
  β = 47

Step 4: Verify
  α + β = 30 + 47 = 77 ✓
  a × b = 77 ✓
  They match!

Now Party A has α=30, Party B has β=47
Neither knows the other's value, but α+β = a×b!
```

**In real crypto**: This uses **Paillier homomorphic encryption**:
```
1. Party B encrypts b: c = Enc(b)
2. Party A computes: c^a × Enc(-α) = Enc(a×b - α)
3. Party B decrypts: β = a×b - α
4. Result: α + β = a×b (and Party A doesn't know b, Party B doesn't know a!)
```

**Try it yourself:**
```rust
let a = 7;
let b = 11;
let (alpha, beta) = EduMTA::convert(a, b);

assert_eq!((alpha + beta) % MODULUS, (a * b) % MODULUS);
```

### 4. Threshold Signature

**Goal**: Multiple parties sign collaboratively without any party knowing the full key.

**Example with small numbers:**
```
Message: "Hello!"
Private key shares: [15, 23, 31] (3 parties)
Challenge (hash): c = 50

Step 1: Each party generates nonce
  Party 0: k₀ = 11
  Party 1: k₁ = 34
  Party 2: k₂ = 57

Step 2: Use MTA to convert k×x for each party
  (In real crypto, this prevents key extraction attacks)
  Result: Each party gets additive shares

Step 3: Each party computes partial signature
  Party 0: s₀ = k₀ + c × (MTA share₀)
  Party 1: s₁ = k₁ + c × (MTA share₁)
  Party 2: s₂ = k₂ + c × (MTA share₂)

Step 4: Combine signatures
  s = s₀ + s₁ + s₂ (mod 97)

Done! The signature is valid without any party knowing the full key.
```

**Try it yourself:**
```rust
let private_key_shares = vec![15, 23, 31];
EduThresholdSignature::sign(&private_key_shares, "Hello!");
```

## Mathematical Foundations

### Modular Arithmetic

All operations use **modulo 97**:
```
Addition:       (a + b) mod 97
Subtraction:    (a - b + 97) mod 97  (add 97 to handle negatives)
Multiplication: (a × b) mod 97
Division:       (a × b⁻¹) mod 97  (multiply by modular inverse)
Exponentiation: (a^b) mod 97
```

**Example calculations:**
```
(95 + 5) mod 97 = 100 mod 97 = 3
(10 - 15) mod 97 = -5 mod 97 = 92
(50 × 60) mod 97 = 3000 mod 97 = 89
```

### Modular Inverse

To divide by `a` mod `p`, multiply by `a⁻¹` (the modular inverse):
```
Find x such that: (a × x) mod p = 1

Example: Find 3⁻¹ mod 97
Using Extended Euclidean Algorithm:
  3 × 65 = 195 = 2×97 + 1
  Therefore: (3 × 65) mod 97 = 1
  So: 3⁻¹ = 65 (mod 97)

Verification: (3 × 65) mod 97 = 195 mod 97 = 1 ✓
```

### Lagrange Interpolation

Given points, find polynomial value at x=0:
```
Given: (x₁, y₁), (x₂, y₂), ..., (xₙ, yₙ)
Find: f(0)

Formula: f(0) = Σ yᵢ × Lᵢ(0)

Where: Lᵢ(0) = Π (0 - xⱼ)/(xᵢ - xⱼ) for j ≠ i

Example: Points (1, 59) and (2, 76)
  L₁(0) = (0-2)/(1-2) = -2/-1 = 2
  L₂(0) = (0-1)/(2-1) = -1/1 = -1 = 96 (mod 97)
  
  f(0) = 59×2 + 76×96 (mod 97)
       = 42
```

## Classroom Activities

### Activity 1: Secret Sharing Relay
1. Students form groups of 5
2. First student picks a secret (0-96)
3. Create 3-of-5 shares by hand
4. Pass shares to 3 other students
5. They reconstruct the secret
6. Verify with original secret

### Activity 2: Verification Challenge
1. Teacher creates shares with one INVALID share
2. Students use Feldman commitments to find the bad share
3. Demonstrates why verification matters!

### Activity 3: MTA Race
1. Two students each have a secret number
2. Convert their product to additive shares
3. Each student only learns their share
4. Class verifies the sum equals the product
5. Demonstrates secure computation!

### Activity 4: Build Your Own
Challenge students to:
- Implement SSS in Python/JavaScript
- Verify the module's outputs by hand
- Find bugs (intentionally planted ones!)
- Optimize the algorithms

## Hand Calculation Worksheet

### Problem 1: Basic Modular Arithmetic
```
Compute (mod 97):
a) 50 + 60 = ?
b) 20 - 30 = ?
c) 8 × 12 = ?
d) Find 7⁻¹ (the inverse of 7)

Answers: a) 13, b) 87, c) 96, d) 42
```

### Problem 2: Secret Sharing
```
Secret: 55
Polynomial: f(x) = 55 + 20x (mod 97)

a) Compute f(1), f(2), f(3)
b) Use f(1) and f(2) to reconstruct the secret

Answers: 
a) f(1)=75, f(2)=95, f(3)=18 
b) Using Lagrange: 55
```

### Problem 3: Feldman VSS
```
Coefficients: a₀ = 30, a₁ = 25
Generator: g = 5

a) Compute commitments C₀ and C₁
b) Compute share at x = 1
c) Verify the share

Answers:
a) C₀ = 5^30 mod 97 = ?, C₁ = 5^25 mod 97 = ?
b) share = 30 + 25×1 = 55 (mod 97)
c) 5^55 ?= C₀ × C₁^1 (mod 97)
```

### Problem 4: MTA
```
a = 6, b = 9

a) Compute a × b (mod 97)
b) Choose α = 40
c) Find β such that α + β = a × b (mod 97)
d) Verify

Answers:
a) 54
b) α = 40
c) β = 14
d) 40 + 14 = 54 ✓
```

## Comparison: Educational vs Production

| Aspect | Educational | Production (ECDSA) |
|--------|-------------|-------------------|
| **Numbers** | ~2 digits | ~77 digits |
| **Modulus** | 97 (prime) | 2²⁵⁶ (curve order) |
| **Operations** | Integer mod p | Elliptic curve points |
| **Verification** | By hand/calculator | Computer only |
| **Security** | NONE - demonstrational | 128-bit security |
| **Key Size** | 7 bits | 256 bits |
| **Performance** | Instant | Milliseconds |
| **Purpose** | Learning | Real-world crypto |

**Key Insight**: The MATH is identical! Only the scale changes.

## Common Pitfalls and Solutions

### Pitfall 1: Negative Modulo
```
Wrong: (5 - 10) mod 97 = -5 (WRONG!)
Right: ((5 - 10) + 97) mod 97 = 92 ✓

Always add the modulus when dealing with subtraction!
```

### Pitfall 2: Division
```
Wrong: 10 ÷ 3 mod 97 (division doesn't exist!)
Right: 10 × 3⁻¹ mod 97 = 10 × 65 mod 97 = 68 ✓

Use modular inverse instead of division!
```

### Pitfall 3: Large Exponents
```
Wrong: Computing 5^42 directly = 22,204,732,500,000 (too big!)
Right: Use modular exponentiation (repeated squaring)
       5^42 mod 97 = 85 (manageable!)
```

## Extensions and Challenges

### Challenge 1: Different Thresholds
Modify the code to use:
- 4-of-7 threshold
- 1-of-1 (no threshold - just encryption/decryption)
- n-of-n (all parties required)

### Challenge 2: Different Primes
Try different small primes:
- p = 101 (slightly larger)
- p = 53 (smaller, easier by hand)
- p = 7 (too small - what breaks?)

### Challenge 3: Malicious Party
Simulate a cheating party:
- Give invalid shares
- Use Feldman VSS to detect them
- Show how verification prevents attacks

### Challenge 4: Real Comparison
- Run educational version
- Run production version  
- Compare outputs conceptually
- See how the math scales up

## Teaching Progression

### Week 1: Foundation
- Modular arithmetic basics
- Exponentiation and inverses
- Polynomial evaluation

### Week 2: Secret Sharing
- Shamir's Secret Sharing concept
- Polynomial construction
- Lagrange interpolation

### Week 3: Verification
- Why verification matters
- Feldman commitments
- Checking shares

### Week 4: MTA
- Multiplication to addition
- Security implications
- Homomorphic encryption concepts

### Week 5: Threshold Signing
- Putting it all together
- Collaborative signatures
- Real-world applications

## Additional Resources

### Online Tools
- Modular arithmetic calculator: https://www.dcode.fr/modular-inverse
- Polynomial grapher: https://www.desmos.com/calculator
- GCD calculator: https://www.calculator.net/gcd-calculator.html

### Video Lessons
- Khan Academy: Modular Arithmetic
- Computerphile: Shamir's Secret Sharing
- 3Blue1Brown: Group Theory

### Books
- "The Code Book" by Simon Singh (popular science)
- "Applied Cryptography" by Bruce Schneier (technical)
- "Cryptography Made Simple" by Smart (mathematical)

## Assessment Ideas

### Quiz Questions
1. Given shares (1, 20) and (2, 35) in a 2-of-3 scheme mod 97, reconstruct the secret
2. Verify if share (3, 45) is valid given commitments C₀=10, C₁=20
3. Convert 8 × 9 into additive shares (show your work)
4. Explain why Feldman VSS is better than plain Shamir SSS

### Project Ideas
1. Implement SSS in a different programming language
2. Create a web app for educational demonstrations
3. Build a "break the crypto" challenge (intentional bugs)
4. Visualize threshold signing with animations

### Lab Exercises
1. Break 1-of-2 secret sharing (show it reveals the secret)
2. Demonstrate 2-of-2 vs 2-of-3 (what's the difference?)
3. Compare MTA with direct multiplication (security implications)
4. Benchmark: educational vs production (performance vs security)

---

## Running the Code

```bash
# View the educational demonstration
cargo run --example educational_demo

# Run all educational tests  
cargo test educational --lib

# View specific test with output
cargo test test_shamir_secret_sharing -- --nocapture

# Compare with production code
cargo run  # Runs main.rs with production crypto
```

## Conclusion

This educational module proves that cryptography doesn't have to be a black box. By scaling down to hand-verifiable numbers, students can:

✅ Understand the mathematical foundations  
✅ Verify every calculation themselves  
✅ Build intuition for cryptographic protocols  
✅ See how concepts scale to production  
✅ Appreciate why real crypto uses big numbers  

The same math that works with modulus 97 works with 2²⁵⁶. The only difference is scale!
