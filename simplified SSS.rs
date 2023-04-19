use curv::{BigInt, FE};
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;

pub struct SSS {
    polynomial: Vec<FE>,
    shares: Vec<FE>,
}

impl SSS {
    pub fn create(secret: &FE, threshold: u32, num_parties: u32) -> Self {
        let mut polynomial = vec![*secret];
        for _ in 1..=threshold {
            polynomial.push(FE::new_random());
        }

        let shares = (1..=num_parties)
            .map(|i| {
                let x = Secp256k1Scalar::from(&BigInt::from(i));
                Self::eval_polynomial(&polynomial, &x)
            })
            .collect::<Vec<_>>();

        Self {
            polynomial,
            shares,
        }
    }

    pub fn polynomial(&self) -> &[FE] {
        &self.polynomial
    }

    pub fn shares(&self) -> &[FE] {
        &self.shares
    }

    fn eval_polynomial(polynomial: &[FE], x: &FE) -> FE {
        let mut result = FE::zero();
        let mut x_pow_i = FE::one();

        for coefficient in polynomial {
            let term = *coefficient * x_pow_i;
            result = result + term;
            x_pow_i = x_pow_i * x;
        }

        result
    }
}
