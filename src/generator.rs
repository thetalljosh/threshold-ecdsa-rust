use k256::{AffinePoint, ProjectivePoint, Scalar, elliptic_curve::{rand_core::OsRng, Field}};

pub fn k256_generator() -> AffinePoint {
AffinePoint::GENERATOR
    }

pub fn proj256_generator() ->ProjectivePoint{
    ProjectivePoint::GENERATOR
    
}

pub fn generate_nonce() -> Scalar {
    Scalar::random(&mut OsRng)
}