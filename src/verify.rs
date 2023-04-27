use k256::{
    AffinePoint, ProjectivePoint, Scalar, elliptic_curve::{sec1::ToEncodedPoint,PrimeField}
};
use sha2::{Digest, Sha256};

pub fn is_valid(
    aggregated_public_key: ProjectivePoint,
    signature: (AffinePoint, Scalar),
    message: &str,
) -> bool {
    // Step 1: Parse the input signature (R, s) and the aggregated public key A
    let r = signature.0;
    let s = signature.1;
    let a = aggregated_public_key;

    // Step 2: Compute the challenge c = H(R || m)
    let mut hasher = Sha256::new();
    hasher.update(r.to_encoded_point(false).as_bytes());
    hasher.update(message.as_bytes());
    let challenge: &k256::Scalar = &k256::Scalar::from_repr_vartime(hasher.finalize()).unwrap();

    // Step 3: Calculate s * G
    let s_times_g = ProjectivePoint::generator() * s;

    // Step 4: Calculate c * A + R
    let c_times_a_plus_r = a * challenge + r;

    // Step 5: Verify that the two values computed in steps 3 and 4 are equal
    println!("Check value 1: {:?}", s_times_g);
    println!("Check value 2: {:?}", c_times_a_plus_r);

    s_times_g.to_affine().eq(&c_times_a_plus_r.to_affine())

}

// Usage:
// let is_valid = custom_verify(aggregated_public_key, signature, message);
// println!("Signature is {}", if is_valid { "valid" } else { "invalid" });
