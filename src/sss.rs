use k256::{Scalar, elliptic_curve::{rand_core::OsRng, Field}};


pub struct SSS {
    polynomial: Vec<Scalar>,
    shares: Vec<Scalar>,
}

impl SSS {
    pub fn create(secret: &Scalar, threshold: u32, num_parties: u32) -> Self {
        let mut polynomial = vec![*secret];
        for _ in 1..threshold {
            polynomial.push(Scalar::random(&mut OsRng));
        }

        let shares = (1..=num_parties)
            .map(|i| {
                let x = Scalar::from(i);
                Self::eval_polynomial(&polynomial, &x)
            })
            .collect::<Vec<_>>();

        Self {
            polynomial,
            shares,
        }
    }

    pub fn polynomial(&self) -> &[Scalar] {
        &self.polynomial
    }

    pub fn shares(&self) -> &[Scalar] {
        &self.shares
    }

    fn eval_polynomial(polynomial: &[Scalar], x: &Scalar) -> Scalar {
        let mut result = Scalar::from(0 as u32);
        let mut x_pow_i = Scalar::from(1 as u32);

        for coefficient in polynomial {
            result += *coefficient * x_pow_i;
            x_pow_i *= x;
        }

        result
    }
}
