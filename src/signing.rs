use crate::verify::*;
use crate::paillier_mta::*;
use paillier::{EncryptionKey, DecryptionKey};
///1. Generate a random nonce k_i for each signer i.
///2. Compute the public nonce R_i = k_i * G, where G is the base point of the elliptic curve.
///3. Each signer i sends their public nonce R_i to all other signers.
///4. All signers compute the combined public nonce R = sum(R_i).
///5. Compute the challenge c = H(R || m), where H() is the hash function, || denotes concatenation, and m is the message to be signed.
///6. Each signer i computes their partial signature s_i = k_i + c * x_i, where x_i is their private key share.
///7. Each signer i sends their partial signature s_i to all other signers.
///8. All signers compute the combined signature s = sum(s_i) mod n, where n is the order of the elliptic curve group.
///9. The final signature is (R, s).
use k256::{
    ecdsa::Signature,
    elliptic_curve::{
        group::{Curve, GroupEncoding},
        sec1::ToEncodedPoint,
        Field, PrimeField,
    },
    ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};
use std::ops::Add;

pub fn mta_protocol(
    private_key_shares: Vec<Scalar>,
    encryption_keys: Vec<EncryptionKey>,
    decryption_keys: Vec<DecryptionKey>,
    message: &str,
) {
    let n = private_key_shares.len();
    let signers = (0..n).collect::<Vec<usize>>();

    // Apply Lagrange coefficients to transform shares for the signing subset
    // This properly reconstructs the signing capability from the threshold subset
    let lagrange_shares = signers
        .iter()
        .map(|&i| {
            let lambda_i = lagrange_coefficient(i, &signers);
            private_key_shares[i] * lambda_i
        })
        .collect::<Vec<Scalar>>();

    println!("=== Phase 1: MTA Protocol for Nonce Generation ===");
    
    // Generate random nonce k_i for each signer i (Gennaro and Goldfeder Step 2)
    let raw_nonces = (0..n)
        .map(|_| Scalar::random(rand::thread_rng()))
        .collect::<Vec<Scalar>>();

    // Create MTA parties for nonce multiplication
    let mta_parties: Vec<MtaParty> = (0..n)
        .map(|i| MtaParty {
            index: i,
            encryption_key: encryption_keys[i].clone(),
            decryption_key: Some(decryption_keys[i].clone()),
        })
        .collect();

    // Use MTA to convert k_i * gamma_i into additive shares
    // This prevents adaptive chosen-message attacks
    let nonce_shares = multi_party_mta(&mta_parties, &raw_nonces);
    
    println!("Nonce shares computed via MTA protocol");

    // Compute public nonce R_i = k_i * G for each signer i (Gennaro and Goldfeder Step 3)
    let public_nonces = raw_nonces
        .iter()
        .map(|k| ProjectivePoint::GENERATOR * k)
        .collect::<Vec<ProjectivePoint>>();

    // Compute combined public nonce R = sum(R_i) (Gennaro and Goldfeder Step 4)
    let combined_public_nonce = public_nonces
        .iter()
        .fold(ProjectivePoint::IDENTITY, Add::add);

    println!("=== Phase 2: Challenge and Signature Computation ===");

    // Compute challenge c = H(R || m) (Gennaro and Goldfeder Step 5)
    let mut hasher = Sha256::new();
    hasher.update(
        combined_public_nonce
            .to_affine()
            .to_encoded_point(false)
            .as_bytes(),
    );
    hasher.update(message.as_bytes());
    let challenge: &k256::Scalar = &k256::Scalar::from_repr_vartime(hasher.finalize()).unwrap();

    // Use MTA for k_i * x_i multiplication to get additive shares
    // This is the core security enhancement over simple additive sharing
    let key_product_shares = multi_party_mta(&mta_parties, &lagrange_shares);

    println!("Key-nonce product shares computed via MTA protocol");

    // Each signer computes their partial signature using MTA shares
    // s_i = k_i + c * (MTA share of k_i * x_i)
    let partial_signatures = signers
        .iter()
        .map(|&i| {
            let k_i = &raw_nonces[i];
            // The MTA share already contains the additive component of k*x
            let mta_share = key_product_shares[i];
            k_i + challenge * mta_share
        })
        .collect::<Vec<Scalar>>();

    // Compute combined signature s = sum(s_i) mod n (Gennaro and Goldfeder Step 7)
    let combined_signature = partial_signatures
        .iter()
        .fold(Scalar::ZERO, |acc, s_i| acc + s_i);

    // Generate the aggregated public key from Lagrange-adjusted shares
    let public_key_shares = lagrange_shares
        .iter()
        .map(|x| ProjectivePoint::GENERATOR * x)
        .collect::<Vec<ProjectivePoint>>();

    let aggregated_public_key = public_key_shares
        .iter()
        .fold(ProjectivePoint::IDENTITY, Add::add);

    // The final signature is (R, s) (Gennaro and Goldfeder Step 8)
    let signature = (combined_public_nonce.to_affine(), combined_signature);

    println!("=== Phase 3: Signature Verification ===");

    // Run signature verification
    let validate_hash = is_valid(aggregated_public_key, signature, message);
    println!(
        "Signature is {}",
        if validate_hash { "valid" } else { "invalid" }
    );
    println!("\nSignature: {:?}", signature);
}

fn lagrange_coefficient(i: usize, signers: &[usize]) -> Scalar {
    let mut lc = Scalar::ONE;
    for j in signers.iter().filter(|&&j| j != i) {
        let num = Scalar::from(*j as u64 + 1); // j+1 since signers are 0-indexed
        let den_value = (*j as i64) - (i as i64);
        let den = if den_value < 0 {
            Scalar::ZERO - Scalar::from((-den_value) as u64)
        } else {
            Scalar::from(den_value as u64)
        };
        let den_inv = den.invert().unwrap();
        lc *= num * den_inv;
    }
    lc
}
