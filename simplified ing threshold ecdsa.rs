use curv::{BigInt, FE, GE};
use curv::elliptic::curves::secp256_k1::GE;
use curv::elliptic::curves::traits::ECPoint;
use paillier::EncryptionKey;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Parameters {
    pub threshold: usize,
    pub num_parties: usize,
    pub paillier_modulus_bits: usize,
}

#[derive(Debug, Clone)]
pub struct Party {
    pub index: PartyIndex,
    pub public_key: Option<GE>,
    pub public_key_share: Option<GE>,
    pub encrypted_shared_secret: Option<EncryptionKey>,
}
pub struct VerifiableSS {
    index: PartyIndex,
    commitments: Vec<GE>,
    shares: Vec<(PartyIndex, FE, ShareProof)>,
}

impl VerifiableSS {
    pub fn new(
        index: PartyIndex,
        commitments: Vec<GE>,
        shares: Vec<(PartyIndex, FE, ShareProof)>,
    ) -> Self {
        VerifiableSS {
            index,
            commitments,
            shares,
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProof {
    pub commitment: GE,
    pub challenge: FE,
    pub response: FE,
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
    secret_key: FE,
    public_key: GE,
    paillier_keypair: Keypair,
}

pub struct VerifiableSS {
    index: PartyIndex,
    commitments: Vec<GE>,
    shares: Vec<(PartyIndex, FE)>,
}

pub struct FeldmanSecretShare {
    index: PartyIndex,
    value: FE,
}

pub struct SharedSecret {
    value: FE,
}

pub struct FinalState {
    params: Parameters,
    parties: Vec<Party>,
    shared_secret: SharedSecret,
    public_key: GE,
}

// Simplified key generation function
pub fn keygen(params: Parameters, parties: Vec<Party>) -> Result<FinalState, KeygenError> {
    let initial_keys = generate_initial_keys(&params, &parties);
    let feldman_vss_schemes = create_feldman_vss_schemes(initial_keys);
    let verified_schemes = verify_feldman_vss_schemes(feldman_vss_schemes)?;
    let shared_secret = combine_shared_secrets(verified_schemes);
    let public_key = compute_public_key(&parties)?;
    let final_state = FinalState {
        params,
        parties,
        shared_secret,
        public_key,
    };
    Ok(final_state)
}

// Generate initial keys for each party
fn generate_initial_keys(params: &Parameters, parties: &Vec<Party>) -> Result<HashMap<PartyIndex, PartyInitialKeys>, KeygenError> {
    let mut initial_keys = HashMap::new();

    for party in parties {
        let party_index = party.index;

        // Generate a random secret key (scalar) for the secp256k1 curve
        let secret_key = FE::new_random();

        // Calculate the corresponding public key (point) for the secp256k1 curve
        let public_key = GE::generator() * secret_key;

        // Generate a Pedersen commitment to the public key using the secret key as the blinding factor
        let mut hasher = Sha256::new();
        hasher.update(public_key.bytes_compressed_to_big_int().to_bytes_be());
        hasher.update(secret_key.to_bytes());
        let commitment = GE::generator() * BigInt::from_bytes_be(SHA256::digest(&hasher.finalize()).as_slice());

        // Generate a Paillier key pair for the party
        let paillier_keypair = match Keypair::with_modulus_size(params.paillier_modulus_bits) {
            Ok(keypair) => keypair,
            Err(e) => return Err(KeygenError::PaillierKeygenError(e.to_string())),
        };

        // Encrypt the shared secret value using the Paillier public key
        let shared_secret = SharedSecret {
            value: FE::new_random(),
        };
        let encrypted_shared_secret = paillier_keypair
            .public_key
            .encrypt(&shared_secret.value.to_big_int().unwrap());

        // Save the secret key, public key, public key share, encrypted shared secret, and Paillier key pair for the party
        let party_initial_keys = PartyInitialKeys {
            secret_key,
            public_key,
            public_key_share: commitment,
            encrypted_shared_secret,
            paillier_keypair,
        };

        initial_keys.insert(party_index, party_initial_keys);
    }

    Ok(initial_keys)
}


// Create Feldman VSS schemes for each party
fn create_feldman_vss_schemes(
    initial_keys: HashMap<PartyIndex, PartyInitialKeys>,
    params: &Parameters,
) -> HashMap<PartyIndex, VerifiableSS> {
    let mut feldman_vss_schemes = HashMap::new();

    for (party_index, party_initial_keys) in initial_keys {
        // Create a Shamir Secret Sharing (SSS) scheme for the party's secret key
        let sss = SSS::create(
            &party_initial_keys.secret_key,
            params.threshold,
            params.num_parties,
        );

        // Calculate the commitments for the Feldman VSS scheme
        let commitments = sss
            .polynomial()
            .iter()
            .map(|coefficient| GE::generator() * coefficient)
            .collect::<Vec<_>>();

        // Create the shares for the Feldman VSS scheme, along with proofs of correctness
        let mut shares = Vec::new();
        for (i, share) in sss.shares().iter().enumerate() {
            let public_share = GE::generator() * share;
            let pedersen_commitment = Pedersen::commit(&public_share, &party_initial_keys.secret_key);
            let encrypted_shared_secret = party_initial_keys.paillier_keypair.public_key.encrypt(&sss.secret());
            let challenge = FE::new_random();
            let response = party_initial_keys.secret_key * challenge + share;
            let proof = ShareProof {
                commitment: pedersen_commitment,
                challenge,
                response,
            };
            let share_with_proof = (i as u32 + 1, public_share, proof);
            shares.push(share_with_proof);
        }

        // Save the Feldman VSS scheme for the party
        let feldman_vss = VerifiableSS {
            index: party_index,
            commitments,
            shares,
        };

        feldman_vss_schemes.insert(party_index, feldman_vss);
    }

    feldman_vss_schemes
}

    

// Verify Feldman VSS schemes and return valid secret shares
fn verify_feldman_vss_schemes(
    feldman_vss_schemes: HashMap<PartyIndex, VerifiableSS>,
    initial_keys: &HashMap<PartyIndex, PartyInitialKeys>,
) -> Result<HashMap<PartyIndex, FeldmanSecretShare>, KeygenError> {
    let mut valid_secret_shares = HashMap::new();

    for (party_index, vss_scheme) in feldman_vss_schemes {
        let party_initial_keys = initial_keys.get(&party_index).ok_or(KeygenError::PublicKeyMissing(party_index))?;

        for (share_index, (share_owner, secret_share, proof)) in vss_scheme.shares.into_iter().enumerate() {
            let public_share_commitment = party_initial_keys.public_key_share.commit(&party_initial_keys.secret_key);

            // Compute the commitment to the share using the public key share commitment and the secret share commitment
            let share_commitment = public_share_commitment + vss_scheme.commitments[share_index];

            // Verify the proof of correctness for the share
            let challenge = BigInt::sample(&mut rand::thread_rng());
            let response = challenge * party_initial_keys.secret_key + BigInt::from(secret_share) * &proof.challenge;

            let expected_commitment = party_initial_keys.public_key_share.commit(&response) + share_commitment * &proof.challenge;

            if expected_commitment == proof.commitment {
                let feldman_secret_share = FeldmanSecretShare {
                    index: *share_owner,
                    value: secret_share.clone(),
                };
                valid_secret_shares.insert(*share_owner, feldman_secret_share);
            } else {
                return Err(KeygenError::InvalidShare(party_index, *share_owner));
            }
        }
    }

    Ok(valid_secret_shares)
}




// Combine shared secrets to obtain the final shared secret
fn combine_shared_secrets(
    secret_shares: HashMap<PartyIndex, FeldmanSecretShare>,
) -> Result<SharedSecret, KeygenError> {
    let mut commitments = Vec::new();
    let mut values = Vec::new();

    for (index, share) in &secret_shares {
        let commitment = share
            .public_key_share
            .commit_to_point(&share.value.to_big_int().unwrap());
        commitments.push(commitment);
        values.push(*index as i64);
    }

    let combined_commitment = curv::cryptographic_primitives::commitments::pedersen::PedersenCommitment::combine_commitments(&commitments)?;
    let combined_secret = curv::cryptographic_primitives::lagrange_interpolation::LagrangeInterpolation::interpolate_at_x(&values, &combined_commitment)?;

    Ok(SharedSecret { value: combined_secret })
}



// Compute the public key using the public key shares and encrypted shared secrets of each party
fn compute_public_key(parties: &Vec<Party>, verified_schemes: &HashMap<PartyIndex, VerifiableSS>, shared_secret: &SharedSecret) -> Result<GE, KeygenError> {
    let mut combined_public_key = GE::identity();

    for party in parties {
        let party_index = party.index;

        // Check that the party has a verified Feldman VSS scheme
        let vss_scheme = match verified_schemes.get(&party_index) {
            Some(vss_scheme) => vss_scheme,
            None => return Err(KeygenError::VSSSchemeMissing(party_index)),
        };

        // Check that the party has a valid secret share
        let secret_share = match vss_scheme.secret_share {
            Some(secret_share) => secret_share,
            None => return Err(KeygenError::SecretShareMissing(party_index)),
        };

        // Decrypt the shared secret using the party's Paillier private key
        let decrypted_shared_secret = match party.paillier_keypair.decrypt(&shared_secret.value.to_big_int().unwrap()) {
            Ok(decrypted_value) => decrypted_value,
            Err(_) => return Err(KeygenError::PaillierDecryptionError(party_index)),
        };

        // Compute a Pedersen commitment to the shared secret using the Pedersen commitment to the public key share as the blinding factor
        let shared_secret_commitment = PedersenCommitment::new(
            &party.public_key_share,
            &decrypted_shared_secret.to_big_int().unwrap(),
        );

        // Compute the public key with the shared secret
        let public_key_with_secret = party.public_key_share + shared_secret_commitment.commitment() * GE::generator();
        combined_public_key = combined_public_key + public_key_with_secret;
    }

    Ok(combined_public_key)
}
