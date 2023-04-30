use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};

use std::collections::HashMap;

use k256::{
    elliptic_curve::{group::prime::PrimeCurveAffine, rand_core::OsRng, Field, PrimeField},
    AffinePoint, Scalar,
};

use thiserror::Error;

use crate::{feldman::*, generator::k256_generator, pedersen::*};
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
    pub secret_share: Option<Scalar>,
    pub encryption_key: Option<EncryptionKey>,
    pub decryption_key: Option<DecryptionKey>,
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
pub fn keygen(params: Parameters, parties: &mut Vec<Party>) -> Result<FinalState, KeygenError> {
    let initial_keys = generate_initial_keys(&params, parties)?;

    //let feldman_vss_schemes = (feldman_vss, secret_shares.clone());
    // Initialize a HashMap to store the Feldman VSS schemes and secret shares for each party
    let mut feldman_vss_schemes: HashMap<PartyIndex, (FeldmanVSS, Vec<Scalar>)> = HashMap::new();

    // Iterate through all parties to create and share the Feldman VSS
    let mut all_secret_shares: Vec<Scalar> = vec![];

    for party_index in 1..=params.num_parties as PartyIndex {
        let (feldman_vss, secret_shares) = FeldmanVSS::share(
            params.threshold,
            params.num_parties,
            &k256::Scalar::from(initial_keys[&party_index].secret_key),
        );
        feldman_vss_schemes.insert(party_index, (feldman_vss, secret_shares.clone()));
            // Iterate through all parties to verify the received shares
    for (party_index, (feldman_vss, secret_shares)) in feldman_vss_schemes.iter() {
        for share_index in 1..=params.num_parties as usize {
            let share = secret_shares[share_index - 1];
            feldman_vss.validate_share(&share, share_index);  
        }
    }
        all_secret_shares.extend(secret_shares.clone());
    }
    // Update each party with their corresponding secret share
    for party in parties.iter_mut() {
        let party_index = party.index as usize;
        let secret_share = feldman_vss_schemes[&(party_index as PartyIndex)].1[party_index - 1];
        party.secret_share = Some(secret_share);
        println!("Party {} share: {:?}\n", party_index, secret_share);
    }

    let shared_secret = combine_shared_secrets(all_secret_shares, initial_keys);
    let public_key = compute_public_key(&parties)?;
    let final_state = FinalState {
        params,
        parties: parties.to_vec(),
        shared_secret,
        public_key,
    };
    Ok(final_state)
}

//Perform the initial key generation to pass into feldman and pedersen functions
fn generate_initial_keys(
    params: &Parameters,
    parties: &mut Vec<Party>,
) -> Result<HashMap<PartyIndex, PartyInitialKeys>, KeygenError> {
    let mut initial_keys = HashMap::new();

    parties.iter_mut().enumerate().for_each(|(i, party)| {
        let party_index = party.index;
        let mut csprng = OsRng;

        //generate the value ui for party pi
        let secret_key = Scalar::random(&mut csprng);
        //println!("Secret key generated: {:?}", secret_key);
        let public_key = k256_generator() * secret_key;

        // Generate a Pedersen commitment to the public key using the secret key as the blinding factor
        let commitment_value = &public_key;
        let commitment =
            Committer::commit(&CommitmentValue(secret_key), &VerifierPublicKey(public_key));

        // Generate a Paillier key pair for the party
        let paillier_keypair = Paillier::keypair();

        // Save the secret key, public_key, public key share, Paillier key pair, and Pedersen commitment for the party
        let party_initial_keys = PartyInitialKeys {
            secret_key,
            public_key: public_key.to_affine(),
            paillier_keypair: paillier_keypair.clone(),
            pedersen_commitment: commitment.0,
        };
        party.public_key = Some(public_key.to_affine());

        initial_keys.insert(party_index, party_initial_keys);

        // Update the Party struct with the Paillier decryption key
        party.encryption_key = Some(paillier_keypair.keys().0.clone());
        party.decryption_key = Some(paillier_keypair.keys().1.clone());
    });

    Ok(initial_keys)
}

pub fn combine_shared_secrets(
    secret_shares: Vec<Scalar>,
    initial_keys: HashMap<u32, PartyInitialKeys>,
) -> SharedSecret {
    let mut shared_secret = Scalar::from(0 as u32);

    for (_, party_initial_keys) in initial_keys {
        shared_secret += party_initial_keys.secret_key;
    }
    //println!("Aggregated Shared Secret: {:?}", shared_secret);
    SharedSecret {
        value: shared_secret,
    }
}
pub fn compute_public_key(parties: &[Party]) -> Result<AffinePoint, KeygenError> {
    let base_point = k256_generator();
    let mut public_key = base_point * Scalar::from(0 as u32);
    let mut public_key_proj = k256::ProjectivePoint::from(public_key);

    for party in parties {
        let party_public_key = party
            .public_key
            .as_ref()
            .ok_or(KeygenError::PointMissing(party.index))?;
        public_key += *party_public_key;
    }
    Ok(public_key.to_affine())
}


/*
pub fn combine_shared_secrets(
    feldman_vss: (FeldmanVSS, Vec<Scalar>),
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
    let base_point = k256_generator();
    let mut public_key = base_point * Scalar::from(0 as u32);

    for (index, secret_share) in secret_shares.iter().enumerate() {
        public_key += base_point * secret_share;
    }

    Ok(public_key.to_affine())
}
*/

