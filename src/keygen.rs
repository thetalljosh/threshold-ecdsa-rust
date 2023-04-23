use paillier::{EncryptionKey, KeyGeneration, Paillier};

use std::collections::HashMap;

use k256::{
    elliptic_curve::{rand_core::OsRng, Field},
    AffinePoint, Scalar
};

use thiserror::Error;

use crate::pedersen::*;
use crate::{feldman::*,k256_generator};

pub type PartyIndex = u32;


#[derive(Debug, Clone)]

pub struct Parameters {
    pub threshold: usize,
    pub num_parties: usize,
    pub paillier_modulus_bits: usize,
}

#[derive(Debug, Clone)]
pub struct Party {
    pub index: PartyIndex,
    pub public_key: Option<AffinePoint>,
    pub public_key_share: Option<AffinePoint>,
    pub encrypted_shared_secret: Option<EncryptionKey>,
}

pub struct VerifiableSS {
    index: PartyIndex,
    commitments: Vec<AffinePoint>,
    shares: Vec<(PartyIndex, Scalar, ShareProof)>,
}

impl VerifiableSS {
    pub fn new(
        index: PartyIndex,
        commitments: Vec<AffinePoint>,
        shares: Vec<(PartyIndex, Scalar, ShareProof)>,
    ) -> Self {
        VerifiableSS {
            index,
            commitments,
            shares,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShareProof {
    pub commitment: AffinePoint,
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Debug, Error)]
pub enum KeygenError {
    #[error("key generation error: {0}")]
    KeygenError(String),
    #[error("Public key missing for party {0}")]
    PointMissing(PartyIndex),
    #[error("Invalid share for party {0}, share index {1}")]
    InvalidShare(PartyIndex, PartyIndex),
}

pub struct PartyInitialKeys {
    secret_key: Scalar,
    public_key: AffinePoint,
    paillier_keypair: paillier::Keypair,
    pedersen_commitment: Commitment,
}

pub struct FeldmanSecretShare {
    index: PartyIndex,
    value: Scalar,
    public_key_share: AffinePoint,
    paillier_keypair: paillier::Keypair,
}

pub struct SharedSecret {
   pub value: Scalar,
}

pub struct FinalState {
    pub params: Parameters,
    pub parties: Vec<Party>,
    pub shared_secret: SharedSecret,
    pub public_key: AffinePoint,
}

//Main Key generation function
pub fn keygen(params: Parameters, parties: Vec<Party>) -> Result<FinalState, KeygenError> {
    let initial_keys = generate_initial_keys(&params, &parties)?;
    let (feldman_vss, secret_shares) = FeldmanVSS::share(
        params.threshold,
        params.num_parties,
        &k256::Scalar::from(
            initial_keys[&1]
                .secret_key
        ),
    );
    let feldman_vss_schemes = (feldman_vss, secret_shares.clone());
    let shared_secret = combine_shared_secrets(feldman_vss_schemes, initial_keys);
    let public_key = compute_public_key(&parties, &secret_shares)?;
    let final_state = FinalState {
        params,
        parties,
        shared_secret,
        public_key,
    };
    Ok(final_state)
}

//Perform the initial key generation to pass into feldman and pedersen functions
fn generate_initial_keys(
    params: &Parameters,
    parties: &Vec<Party>,
) -> Result<HashMap<PartyIndex, PartyInitialKeys>, KeygenError> {
    let mut initial_keys = HashMap::new();

    for party in parties {
        let party_index = party.index;
        let mut csprng = OsRng;

        let secret_key = Scalar::random(&mut csprng);
        let public_key =k256_generator() * secret_key;

        // *K256_GENERATORenerate a Pedersen commitment to the public key using the secret key as the blinding factor
        let commitment_value = &public_key;
        let commitment = Committer::commit(&CommitmentValue(secret_key), &VerifierPublicKey(public_key));
        // *K256_GENERATORenerate a Paillier key pair for the party
        let paillier_keypair = Paillier::keypair();

        // Save the secret key, public key, public key share, Paillier key pair, and Pedersen commitment for the party
        let party_initial_keys = PartyInitialKeys {
            secret_key,
            public_key: public_key.to_affine(),
            paillier_keypair,
            pedersen_commitment: commitment.0,
        };

        initial_keys.insert(party_index, party_initial_keys);
    }

    Ok(initial_keys)
}


pub fn combine_shared_secrets(
    feldman_vss: (FeldmanVSS, Vec<k256::Scalar>),
    initial_keys: HashMap<u32, PartyInitialKeys>,
) -> SharedSecret {
    let (vss, secret_shares) = feldman_vss;
    let num_shares = vss.parameters.share_count;

    // Extract the secret shares and their indices
    let shares = secret_shares
        .into_iter()
        .enumerate()
        .map(|(index, share)| (index, share))
        .collect::<Vec<(usize, Scalar)>>();

    // Reconstruct the shared secret using the FeldmanVSS implementation
    let shared_secret = vss.reconstruct(
        &shares.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        &shares.iter().map(|(_, share)| *share).collect::<Vec<_>>(),
    );

    SharedSecret {
        value: shared_secret,
    }
}


pub fn compute_public_key(
    parties: &[Party],
    secret_shares: &Vec<Scalar>,
) -> Result<AffinePoint, KeygenError> {
    let base_point =k256_generator();
    let mut public_key = base_point * Scalar::from(0 as u32);

    for (index, secret_share) in secret_shares.iter().enumerate() {
        public_key += base_point * secret_share;
    }

    Ok(public_key.to_affine())
}