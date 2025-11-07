use gennaro_rs::{
    keygen::{keygen, Parameters, Party},
    proj256_generator,
    signing::mta_protocol,
    PartyIndex,
};
use k256::elliptic_curve::{rand_core::OsRng, Field, ProjectivePoint, Scalar};
use num_bigint::{BigInt, BigUint};
use paillier::{Encrypt, KeyGeneration, Paillier};
use rand::Rng;
use sha2::digest::HashMarker;

fn main() {
    // The message to be signed by the threshold ECDSA protocol
    let message: &str = "Hello, world!";

    // Define the parameters for the key generation process, including the threshold, the number of parties, and the Paillier key bit length
    let params = Parameters {
        threshold: 3,
        num_parties: 5,
        paillier_modulus_bits: 2048,
    };

    // Initialize the parties for the threshold ECDSA protocol
    let mut parties = initialize_parties(params.num_parties);

    // Execute the key generation process to generate the shared secret and public keys
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
            println!("Key generation successful!\n");
            println!(
                "Aggregated Private key: {:?}\n",
                final_state.shared_secret.value
            );
            println!("Aggregated Public key: {:?}\n", final_state.public_key);

            // Extract the private key shares from a threshold subset of parties (3 out of 5)
            // Using parties at indices 1, 2, and 3 (0-based: parties[1], parties[2], parties[3])
            // This demonstrates that any t parties can sign without needing all n parties
            let signing_parties_indices = vec![1, 2, 3]; // Parties 2, 3, 4 in 1-based indexing
            let private_key_shares = signing_parties_indices
                .iter()
                .filter_map(|&idx| parties[idx].secret_share)
                .collect::<Vec<_>>();

            // Extract Paillier encryption and decryption keys for MTA protocol
            let encryption_keys = signing_parties_indices
                .iter()
                .filter_map(|&idx| parties[idx].encryption_key.clone())
                .collect::<Vec<_>>();

            let decryption_keys = signing_parties_indices
                .iter()
                .filter_map(|&idx| parties[idx].decryption_key.clone())
                .collect::<Vec<_>>();

            println!(
                "Signing with {} out of {} parties (indices: {:?})\n",
                private_key_shares.len(),
                params.num_parties,
                signing_parties_indices
                    .iter()
                    .map(|&i| i + 1)
                    .collect::<Vec<_>>()
            );

            // Execute the MTA protocol to sign the message using the private key shares
            // Now includes Paillier keys for secure multiplicative-to-additive conversion
            mta_protocol(private_key_shares, encryption_keys, decryption_keys, message);
        }
        Err(e) => {
            println!("Key generation failed: {}", e);
        }
    }
}

// Initialize a Vec of Party structs with the given number of parties
fn initialize_parties(num_parties: usize) -> Vec<Party> {
    // Populate the Vec with empty Party structs, each with a unique index
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
