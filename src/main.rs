use gennaro_rs::{keygen::{Parameters, Party, keygen}, proj256_generator, signing::mta_protocol, PartyIndex};
use k256::elliptic_curve::{Scalar, rand_core::OsRng, ProjectivePoint, Field};
use num_bigint::{BigUint, BigInt};
use paillier::{Paillier, KeyGeneration, Encrypt};
use rand::Rng;
use sha2::digest::HashMarker;

fn main() {

    let message: &str = "Hello, world!";

    // Define the parameters for the key generation process
    let params = Parameters {
        threshold: 3,
        num_parties: 5,
        paillier_modulus_bits: 2048,
    };

    // Create a list of parties
    let mut parties = initialize_parties(params.num_parties);

    // Run the key generation process
    let keygen_result = keygen(params, &mut parties);

    match keygen_result {
        Ok(final_state) => {
            parties.iter().enumerate().for_each(|(i, party)| {
                /*
                println!("Party {}:\n",party.index);
                println!("Public key: {:?}",party.public_key);
                println!("Public key share: {:?}", party.public_key_share);
                println!("Paillier Encryption Key: {:?}",party.encryption_key);
                println!("Paillier Decryption Key: {:?}",party.decryption_key);
                println!("Party Secret Share: {:?}\n",party.secret_share);
                */
            });
            println!("Key generation successful!");
            println!("Aggregated Private key: {:?}", final_state.shared_secret.value);
            println!("Aggregated Public key: {:?}", final_state.public_key);
        }
        Err(e) => {
            println!("Key generation failed: {}", e);
        }
    }

    // Extract private key shares from parties
    let private_key_shares = parties[1..3]
    .iter()
    .filter_map(|party| party.secret_share.as_ref())
    .cloned()
    .collect();

// Call mta_protocol with the private key shares
mta_protocol(private_key_shares, message);

}

fn initialize_parties(num_parties: usize) -> Vec<Party> {
    (1..=num_parties as PartyIndex)
        .map(|i| Party {
            index: i,
            public_key: None,
            public_key_share: None,
            secret_share: None,
            encryption_key: None,
            decryption_key: None,
        })
        .collect()
}