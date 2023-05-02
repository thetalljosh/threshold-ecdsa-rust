use std::ops::Mul;

use k256::{
    elliptic_curve::{rand_core::OsRng, Field},
    schnorr::{self, Error},
    AffinePoint, ProjectivePoint, Scalar, Secp256k1,
};
use serde::{Deserialize, Serialize};

use crate::k256_generator;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ShamirSecretSharing {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Clone, PartialEq, Debug)]
pub struct FeldmanVSS {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<ProjectivePoint>,
}
impl FeldmanVSS {
    pub fn share(t: usize, n: usize, secret: &Scalar) -> (FeldmanVSS, Vec<Scalar>) {
        assert!(t < n);

        let poly = FeldmanVSS::sample_polynomial(t, secret);

        let index_vec: Vec<usize> = (1..=n).collect();
        let secret_shares = FeldmanVSS::evaluate_polynomial(&poly, &index_vec);

        let secp: Secp256k1 = Secp256k1;
        let commitments = (0..poly.len())
            .map(|i| ProjectivePoint::from((k256_generator()).mul(&poly[i])))
            .collect::<Vec<ProjectivePoint>>();

        (
            FeldmanVSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
            },
            secret_shares,
        )
    }

    pub fn share_at_indices(
        t: usize,
        n: usize,
        secret: &Scalar,
        index_vec: &[usize],
    ) -> (FeldmanVSS, Vec<Scalar>) {
        assert_eq!(n, index_vec.len());
        let poly = FeldmanVSS::sample_polynomial(t, secret);
        let secret_shares = FeldmanVSS::evaluate_polynomial(&poly, index_vec);

        let commitments = (0..poly.len())
            .map(|i| ((k256_generator()).mul(&poly[i])))
            .collect::<Vec<ProjectivePoint>>();
        (
            FeldmanVSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
            },
            secret_shares,
        )
    }

    pub fn sample_polynomial(t: usize, coef0: &Scalar) -> Vec<Scalar> {
        let mut rng = OsRng;

        let mut coefficients = vec![*coef0];
        let random_coefficients: Vec<Scalar> = (0..t).map(|_| Scalar::random(rng)).collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    pub fn evaluate_polynomial(coefficients: &[Scalar], index_vec: &[usize]) -> Vec<Scalar> {
        (0..index_vec.len())
            .map(|point| {
                FeldmanVSS::mod_evaluate_polynomial(
                    coefficients,
                    Scalar::from(index_vec[point] as u32),
                )
            })
            .collect::<Vec<Scalar>>()
    }

    pub fn mod_evaluate_polynomial(coefficients: &[Scalar], point: Scalar) -> Scalar {
        let mut result = Scalar::from(0 as u32);
        for c in coefficients.iter().rev() {
            result = result.mul(&point).add(c);
        }
        result
    }

    pub fn reconstruct(&self, indices: &[usize], shares: &[Scalar]) -> Scalar {
        let points = indices
            .iter()
            .map(|i| Scalar::from(*i as u32 + 1))
            .collect::<Vec<_>>();
        FeldmanVSS::lagrange_interpolation_at_zero(&points, &shares)
    }

    /// Performs a Lagrange interpolation in field Zp at the origin
    /// for a polynomial defined by `points` and `values`.
    /// `points` and `values` are expected to be two arrays of the same size, containing
    /// respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).
    /// The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.

    pub fn lagrange_interpolation_at_zero(points: &[Scalar], values: &[Scalar]) -> Scalar {
        // Ensure the length of points and values is the same
        assert_eq!(points.len(), values.len());

        let n = points.len();
        let mut acc = Scalar::ZERO;

        // Perform Lagrange interpolation
        for i in 0..n {
            let xi = &points[i];
            let yi = &values[i];
            let mut num: Scalar = Scalar::from(1 as u32);
            let mut den: Scalar = Scalar::from(1 as u32);

            for j in 0..n {
                if i != j {
                    let xj = &points[j];
                    // Compute the numerator and denominator of the Lagrange coefficient
                    num *= xj;
                    den *= xj - xi;
                }
            }
            // Invert the denominator
            let den_inv = den.invert().unwrap();
            // Add the term for this index to the accumulator
            acc += yi * &num * den_inv;
        }

        // Return the reconstructed secret key
        acc
    }

    pub fn validate_share(&self, secret_share: &Scalar, index: usize) -> Result<(), Error> {
        let ss_point = k256_generator() * secret_share;
        self.validate_share_public(&ss_point, index)
    }

    pub fn validate_share_public(
        &self,
        ss_point: &ProjectivePoint,
        index: usize,
    ) -> Result<(), Error> {
        if index >= self.commitments.len() {
            return Err(schnorr::Error::new());
        }

        let comm_to_point = self.get_point_commitment(index);
        if *ss_point == comm_to_point {
            Ok(())
        } else {
            Err(schnorr::Error::new())
        }
    }

    pub fn get_point_commitment(&self, index: usize) -> AffinePoint {
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        let mut index_fe = Scalar::from(index as u32);
        let comm_to_point = tail.fold(head.clone(), |acc, x| *x + acc * index_fe);
        comm_to_point.into()
    }

    // Compute \lambda_{index,S}, a Lagrangian coefficient that changes the (t,n) scheme to (|S|,|S|)
    pub fn map_share_to_new_params(&self, index: u32, s: &[usize]) -> Scalar {
        let s_len = s.len();
        let num: Scalar = Scalar::from(1 as u32);
        let den: Scalar = Scalar::from(1 as u32);

        let points = (0..self.parameters.share_count)
            .map(|i| ((i as u32) + 1))
            .collect::<Vec<_>>();

        let xi = points[index as usize];
        let num = (0..s_len).fold(num, |acc, i| {
            if s[i] != index as usize {
                acc.mul(Scalar::from(points[s[i]]))
            } else {
                acc
            }
        });
        let denum = (0..s_len).fold(den, |acc, j| {
            // Changed variable from i to j
            if s[j] != index as usize {
                let xj_sub_xi = points[s[j]] - xi; // Changed variable from i to j
                acc.mul(Scalar::from(xj_sub_xi))
            } else {
                acc
            }
        });

        num * denum.invert().unwrap()
    }
}
