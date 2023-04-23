use crate::k256_generator;
use k256::{
    elliptic_curve::{rand_core::OsRng, Field},
    ProjectivePoint, Scalar,
};

pub struct Commitment(ProjectivePoint);

pub struct CommitmentOpening(Scalar);

#[derive(Clone)]
pub struct VerifierPublicKey(pub ProjectivePoint);

pub struct CommitmentValue(pub Scalar);

pub struct Committer;

pub struct CommitVerifier {
    pk: VerifierPublicKey,
    commitment: Option<Commitment>,
}

impl CommitmentValue {
    pub fn from_u64(x: u64) -> Self {
        CommitmentValue(Scalar::from(x))
    }
}

impl CommitVerifier {
    pub fn init() -> (VerifierPublicKey, Self) {
        let mut csprng = OsRng;
        let a = Scalar::random(&mut csprng);
        let H = k256_generator() * a;
        let pub_key = VerifierPublicKey(H);
        (
            pub_key.clone(),
            CommitVerifier {
                pk: pub_key,
                commitment: None,
            },
        )
    }

    pub fn receive_commitment(&mut self, commitment: Commitment) {
        self.commitment = Some(commitment);
    }

    pub fn verify(&self, val: &CommitmentValue, commitment_opening: &CommitmentOpening) -> bool {
        if let Some(Commitment(C)) = &self.commitment {
            let VerifierPublicKey(H) = &self.pk;
            let CommitmentOpening(r) = commitment_opening;
            let CommitmentValue(m) = val;
            let C2 = k256_generator() * r + H * m;
            C == &C2
        } else {
            panic!("No commitment received");
        }
    }
}

impl Committer {
    pub fn commit(
        val: &CommitmentValue,
        pk: &VerifierPublicKey,
    ) -> (Commitment, CommitmentOpening) {
        let mut csprng = OsRng;
        let r = Scalar::random(&mut csprng);
        let &CommitmentValue(val_scalar) = val;
        let &VerifierPublicKey(pub_key_point) = pk;
        let C = k256_generator() * r + pub_key_point * val_scalar;
        (Commitment(C), CommitmentOpening(r))
    }
}
