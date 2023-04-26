///1. Generate a random nonce k_i for each signer i.
///2. Compute the public nonce R_i = k_i * G, where G is the base point of the elliptic curve.
///3. Each signer i sends their public nonce R_i to all other signers.
///4. All signers compute the combined public nonce R = sum(R_i).
///5. Compute the challenge c = H(R || m), where H() is the hash function, || denotes concatenation, and m is the message to be signed.
///6. Each signer i computes their partial signature s_i = k_i + c * x_i, where x_i is their private key share.
///7. Each signer i sends their partial signature s_i to all other signers.
///8. All signers compute the combined signature s = sum(s_i) mod n, where n is the order of the elliptic curve group.
///9. The final signature is (R, s).

use k256::{elliptic_curve::{FieldBytes, Field,sec1::ToEncodedPoint, PrimeField, CurveArithmetic, Curve}, Scalar, ProjectivePoint, AffinePoint};
use sha2::{Digest, Sha256};
use std::ops::Add;

pub fn mta_protocol(private_key_shares: Vec<Scalar>) {
    // example message
    let message = b"Hello, world!";

    // Generate private key shares and their corresponding public key shares
    //let private_key_shares = vec![Scalar::random(rand::thread_rng()); 3];
    let public_key_shares = private_key_shares
        .iter()
        .map(|x| ProjectivePoint::generator() * x)
        .collect::<Vec<ProjectivePoint>>();

    // Compute the aggregated public key
    let aggregated_public_key = public_key_shares.iter().fold(ProjectivePoint::identity(), Add::add);

    // 1. Generate random nonce k_i for each signer i
    let nonces = private_key_shares
        .iter()
        .map(|_| Scalar::random(rand::thread_rng()))
        .collect::<Vec<Scalar>>();

    // 2. Compute public nonce R_i = k_i * G for each signer i
    let public_nonces = nonces
        .iter()
        .map(|k| ProjectivePoint::generator() * k)
        .collect::<Vec<ProjectivePoint>>();

    // 3 & 4. Compute combined public nonce R = sum(R_i)
    let combined_public_nonce = public_nonces.iter().fold(ProjectivePoint::identity(), Add::add);

    // 5. Compute challenge c = H(R || m)
    let mut hasher = Sha256::new();
    hasher.update(combined_public_nonce.to_affine().to_encoded_point(false).as_bytes());
    hasher.update(message);
    let challenge: &k256::Scalar = &k256::Scalar::from_repr_vartime((hasher.finalize())).unwrap();

    // 6. Each signer computes their partial signature s_i = k_i + c * x_i
    let partial_signatures = nonces
        .iter()
        .zip(private_key_shares.iter())
        .map(|(k_i, x_i)| k_i + challenge * x_i)
        .collect::<Vec<Scalar>>();

    // 7 & 8. Compute combined signature s = sum(s_i) mod n
    let combined_signature = partial_signatures
        .iter()
        .fold(Scalar::ZERO, |acc, s_i| acc + s_i);

    // 9. The final signature is (R, s)
    let signature = (combined_public_nonce.to_affine(), combined_signature);

    println!("\nSignature: {:?}", signature);
}
