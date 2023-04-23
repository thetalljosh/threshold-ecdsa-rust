use paillier::{Encrypt, EncryptionKey, KeyGeneration, Keypair, Paillier};

//use secp256k1::rand::rngs::OsRng;
//use secp256k1::{constants, All, Scalar, Secp256k1};
//use secp256k1::{ecdsa::Signature, KeyPair, Message, PublicKey, SecretKey, serde};

use sha2::digest::crypto_common::Key;
use sha2::{Digest, Sha256, Sha512, Sha512_256};

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::ops::Mul;

use k256::{Scalar, ProjectivePoint, elliptic_curve::{rand_core::OsRng, Field}, Secp256k1, schnorr::{Error, self}, AffinePoint};

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use num_bigint::{BigInt, ToBigInt};
use num_traits::identities::One;
use num_traits::identities::Zero;
use num_traits::sign;

use thiserror::Error;

use crate::{feldman::*, k256_generator};
use crate::pedersen::*;
use crate::sss::*;

pub type PartyIndex = u32;

const G: Scalar = k256_generator();

#[derive(Debug, Clone)]

pub struct Parameters {
    pub threshold: usize,
    pub num_parties: usize,
    pub paillier_modulus_bits: usize,
}

pub struct Commitment(PublicKey);

#[derive(Debug, Clone)]
pub struct Party {
    pub index: PartyIndex,
    pub public_key: Option<PublicKey>,
    pub public_key_share: Option<PublicKey>,
    pub encrypted_shared_secret: Option<EncryptionKey>,
}

pub struct VerifiableSS {
    index: PartyIndex,
    commitments: Vec<PublicKey>,
    shares: Vec<(PartyIndex, SecretKey, ShareProof)>,
}

impl VerifiableSS {
    pub fn new(
        index: PartyIndex,
        commitments: Vec<PublicKey>,
        shares: Vec<(PartyIndex, SecretKey, ShareProof)>,
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
    pub commitment: PublicKey,
    pub challenge: SecretKey,
    pub response: SecretKey,
}

#[derive(Debug, Error)]
pub enum KeygenError {
    #[error("Paillier key generation error: {0}")]
    PaillierKeygenError(String),
    #[error("Public key missing for party {0}")]
    PublicKeyMissing(PartyIndex),
    #[error("Invalid share for party {0}, share index {1}")]
    InvalidShare(PartyIndex, PartyIndex),
}

pub struct PartyInitialKeys {
    secret_key: SecretKey,
    public_key: PublicKey,
    shared_secret: secp256k1::KeyPair,
    public_key_share: Commitment,
    paillier_keypair: paillier::Keypair,
    pedersen_commitment: Commitment,
}

pub struct FeldmanSecretShare {
    index: PartyIndex,
    value: SecretKey,
    public_key_share: PublicKey,
    paillier_keypair: paillier::Keypair,
}

pub struct SharedSecret {
    value: SecretKey,
    paillier_keypair: paillier::Keypair,
}

pub struct FinalState {
    params: Parameters,
    parties: Vec<Party>,
    shared_secret: SharedSecret,
    public_key: PublicKey,
}

// Simplified key generation function

pub fn keygen(params: Parameters, parties: Vec<Party>) -> Result<FinalState, KeygenError> {
    let initial_keys = generate_initial_keys(&params, &parties)?;
    let feldman_vss_schemes = FeldmanVSS::share(params.threshold, params.num_parties, &k256::Scalar::from(initial_keys[&1].secret_key.secret_bytes().try_into().unwrap()));
    //let verified_schemes = verify_feldman_vss_schemes(feldman_vss_schemes, &initial_keys)?;
    let shared_secret = combine_shared_secrets(feldman_vss_schemes)?;
    let public_key = compute_public_key(&parties, &feldman_vss_schemes, &shared_secret)?;
    let final_state = FinalState {
        params,
        parties,
        shared_secret,
        public_key,
    };
    Ok(final_state)
}

fn generate_initial_keys(
    params: &Parameters,
    parties: &Vec<Party>,
) -> Result<HashMap<PartyIndex, PartyInitialKeys>, KeygenError> {
    let mut initial_keys = HashMap::new();

    for party in parties {
        let secp = Secp256k1::new();
        let party_index = party.index;
        let mut csprng = OsRng;

        let secret_key = SecretKey::new(&mut csprng);
        let shared_secret = secp256k1::KeyPair::new(&secp, &mut csprng);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Generate a Pedersen commitment to the public key using the secret key as the blinding factor
        let blinding_factor = secret_key.clone();
        let public_key_point = public_key;
        let commitment = pedersen_commit(&public_key_point, &blinding_factor, secp);

        // Generate a Paillier key pair for the party
        let paillier_keypair = Paillier::keypair();

        // Save the secret key, public key, public key share, and Paillier key pair for the party
        let party_initial_keys = PartyInitialKeys {
            secret_key,
            public_key: public_key,
            public_key_share: commitment,
            shared_secret,
            paillier_keypair,
            pedersen_commitment: commitment,
        };

        initial_keys.insert(party_index, party_initial_keys);
    }

    Ok(initial_keys)
}

/*
// Verify Feldman VSS schemes and return valid secret shares
fn verify_feldman_vss_schemes(
    feldman_vss_schemes: HashMap<PartyIndex, VerifiableSS>,
    initial_keys: &HashMap<PartyIndex, PartyInitialKeys>,
) -> Result<HashMap<PartyIndex, FeldmanSecretShare>, KeygenError> {
    let mut valid_secret_shares = HashMap::new();

    for (party_index, vss_scheme) in feldman_vss_schemes {
        let party_initial_keys = initial_keys
            .get(&party_index)
            .ok_or(KeygenError::PublicKeyMissing(party_index))?;

        for (share_index, (share_owner, secret_share, proof)) in
            vss_scheme.shares.into_iter().enumerate()
        {
            let public_share_commitment = party_initial_keys.public_key_share.0;

            // Compute the commitment to the share using the public key share commitment and the secret share commitment
            let share_commitment = RistrettoPoint::from(public_share_commitment)
                + vss_scheme.commitments[share_index].decompress().unwrap();

            // Verify the proof of correctness for the share
            let expected_commitment = share_commitment.mul(proof.challenge.into())
                + (ED25519_BASEPOINT_POINT * proof.response).compress();

            if expected_commitment == proof.commitment {
                let feldman_secret_share = FeldmanSecretShare {
                    index: share_owner,
                    value: secret_share.clone(),
                    public_key_share: party_initial_keys.public_key_share.0.compress(),
                    paillier_keypair: party_initial_keys.paillier_keypair,
                };
                valid_secret_shares.insert(share_owner, feldman_secret_share);
            } else {
                return Err(KeygenError::InvalidShare(party_index, share_owner));
            }
        }
    }

    Ok(valid_secret_shares)
}
*/

// Combine shared secrets and return the resulting shared secret
pub fn combine_shared_secrets(
    feldman_vss: FeldmanVSS,
    vec: Vec<k256::Scalar>,
) -> Result<SharedSecret, KeygenError> {
    let num_shares = feldman_vss.parameters.share_count;

    // Extract the secret shares and their indices
    let shares = vec
        .into_iter()
        .enumerate()
        .map(|(index, share)| (index, share))
        .collect::<Vec<(usize, Scalar)>>();

    // Reconstruct the shared secret using the FeldmanVSS implementation
    let shared_secret = feldman_vss.reconstruct(
        &shares.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        &shares.iter().map(|(_, share)| *share).collect::<Vec<_>>(),
    );

    let paillier_keypair = Paillier::keypair();

    let combined_public_key_share = public_key_shares.iter().fold(
        ED25519_BASEPOINT_POINT * Scalar::zero(),
        |acc, (index, share)| acc + (ED25519_BASEPOINT_POINT * share),
    );

    let mut public_keys = vec![];
    let mut paillier_public_keys = vec![];
    let mut paillier_secret_keys = vec![];

    for (index, secret_share) in valid_secret_shares {
        public_keys.push(secret_share.public_key_share);
        paillier_public_keys.push(secret_share.paillier_keypair.public_key());
        paillier_secret_keys.push(secret_share.paillier_keypair.secret_key());
    }

    let combined_public_key = combine_public_keys(&public_keys)?;
    let paillier_keypair = Paillier::keypair();

    Ok(SharedSecret {
        value: shared_secret,
        paillier_keypair,
    })
}

pub fn compute_public_key(
    parties: &[Party],
    verified_schemes: &HashMap<PartyIndex, FeldmanSecretShare>,
    shared_secret: &SharedSecret,
) -> Result<CompressedRistretto, KeygenError> {
    let mut public_key = ED25519_BASEPOINT_POINT * Scalar::zero();
    for party in parties {
        let secret_share = verified_schemes.get(&party.index).unwrap().value;
        public_key += ED25519_BASEPOINT_POINT * secret_share;
    }
    let public_key_share = shared_secret.paillier_keypair.p;
    let final_key = CompressedEdwardsY(
        public_key.try_into() + (public_key_share.try_into().unwrap() as [u8; 32]),
    );
    Ok(final_key.compress())
}

fn lagrange_interpolate(secrets: &[Scalar]) -> Result<Scalar, KeygenError> {
    let num_shares = secrets.len();

    if num_shares < 1 {
        return Err(KeygenError::InvalidShare(0, 0));
    }

    let mut result = Scalar::zero();

    for (i, secret_i) in secrets.iter().enumerate() {
        let mut numerator = Scalar::one();
        let mut denominator = Scalar::one();

        for (j, secret_j) in secrets.iter().enumerate() {
            if i == j {
                continue;
            }

            let x_i = Scalar::from(i as u64);
            let x_j = Scalar::from(j as u64);

            numerator *= x_j;
            denominator *= x_j - x_i;
        }

        let lagrange_term = *secret_i * (numerator * denominator.invert());
        result += lagrange_term;
    }

    Ok(result)
}

// Compute the Pedersen commitment of a value `value` using a blinding factor `blinding_factor`
pub fn pedersen_commit(
    value: &PublicKey,
    blinding_factor: &SecretKey,
    secp: Secp256k1<All>,
) -> Commitment {

    // Create a hash of the generator point as an additional generator
    let h_bytes = {
        let mut hasher = Sha256::new();
        hasher.update(&G.to_string());
        hasher.finalize()
    };

    let h = PublicKey::from_slice(&h_bytes).unwrap();

    let blinded_value = value
        .mul_tweak(&secp, &Scalar::from(*blinding_factor))
        .unwrap();
    let blinded_h = h.mul_tweak(&secp, &Scalar::from(*blinding_factor)).unwrap();
    let blinded_key = PublicKey::combine(&blinded_value, &blinded_h).unwrap();
    let commitment = PublicKey::combine(&value, &blinded_key).unwrap();

    Commitment(commitment)
}

