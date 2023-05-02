use crate::verify::*;
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

pub fn mta_protocol(private_key_shares: Vec<Scalar>, message: &str) {
    let n = private_key_shares.len();
    let signers = (0..n).collect::<Vec<usize>>();

    // Generate private key shares and their corresponding public key shares
    let public_key_shares = private_key_shares
        .iter()
        .map(|x| ProjectivePoint::GENERATOR * x)
        .collect::<Vec<ProjectivePoint>>();

    // Compute the aggregated public key by summing the public key shares (Gennaro and Goldfeder Step 1)
    let aggregated_public_key = public_key_shares
        .iter()
        .fold(ProjectivePoint::IDENTITY, Add::add);


    // Generate random nonce k_i for each signer i(Gennaro and Goldfeder Step 2)
    let nonces = private_key_shares
        .iter()
        .map(|_| Scalar::random(rand::thread_rng()))
        .collect::<Vec<Scalar>>();

    // // Compute public nonce R_i = k_i * G for each signer i (Gennaro and Goldfeder Step 3)
    let public_nonces = nonces
        .iter()
        .map(|k| ProjectivePoint::GENERATOR * k)
        .collect::<Vec<ProjectivePoint>>();

    // Compute combined public nonce R = sum(R_i) (Gennaro and Goldfeder Step 4)
    let combined_public_nonce = public_nonces
        .iter()
        .fold(ProjectivePoint::IDENTITY, Add::add);

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

  // Each signer computes their partial signature s_i = k_i + c * x_i (Gennaro and Goldfeder Step 6)
    let partial_signatures = signers
        .iter()
        .map(|i| {
            let k_i = &nonces[*i];
            let x_i = &private_key_shares[*i];
            k_i + challenge * x_i
        })
        .collect::<Vec<Scalar>>();

   // Compute combined signature s = sum(s_i) mod n (Gennaro and Goldfeder Step 7)
    let combined_signature = partial_signatures
        .iter()
        .fold(Scalar::ZERO, |acc, s_i| acc + s_i);
    
    
    // The final signature is (R, s) (Gennaro and Goldfeder Step 8)
    let signature = (combined_public_nonce.to_affine(), combined_signature);

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
        let den = Scalar::from(((i as i64) - (*j as i64)) as u64); // i-j
        let den_inv = den.invert().unwrap();
        lc *= num * den_inv;
    }
    lc
}
