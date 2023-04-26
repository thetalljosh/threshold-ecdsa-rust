use gennaro_rs::{keygen::{Parameters, Party, keygen}, gen_nonce, signing::{*, self}, proj256_generator};
use k256::elliptic_curve::{Scalar, rand_core::OsRng, ProjectivePoint};
use num_bigint::{BigUint, BigInt};
use paillier::{Paillier, KeyGeneration, Encrypt};
use rand::Rng;
use sha2::digest::HashMarker;

fn main() {
    // Define the parameters for the key generation process
    let parameters = Parameters {
        threshold: 3,
        num_parties: 5,
        paillier_modulus_bits: 2048,
    };

    // Create a list of parties
    let parties = vec![
        Party {
            index: 1,
            public_key: None,
            public_key_share: None,
            encrypted_shared_secret: None,
        },
        Party {
            index: 2,
            public_key: None,
            public_key_share: None,
            encrypted_shared_secret: None,
        },
        Party {
            index: 3,
            public_key: None,
            public_key_share: None,
            encrypted_shared_secret: None,
        },
        Party {
            index: 4,
            public_key: None,
            public_key_share: None,
            encrypted_shared_secret: None,
        },
        Party {
            index: 5,
            public_key: None,
            public_key_share: None,
            encrypted_shared_secret: None,
        },
    ];

    // Run the key generation process
    match keygen(parameters, parties) {
        Ok(final_state) => {
            println!("Key generation successful!");
            println!("Shared secret: {:?}", final_state.shared_secret.value);
            println!("Public key: {:?}", final_state.public_key);
        }
        Err(e) => {
            println!("Key generation failed: {}", e);
        }
    }
    println!("Signing Nonce: {:?}", gen_nonce());
    let m2 = "Shh";

    let alice = parties[0];
    let bob = parties[1];

    let (alice_pk, alice_sk) = (alice.public_key_share.unwrap(), alice.encrypted_shared_secret.unwrap());
    let (bob_pk, bob_sk) = (bob.public_key_share.unwrap(), bob.encrypted_shared_secret.unwrap());

    // Secret-shared values a_i (held by Pi) and b_j (held by Pj)
    let a_i = alice_pk.into();
    let b_j = bob_pk.into();

    // For demonstration purposes, generate Paillier key pairs for Alice and Bob
    let (alice_ek, alice_dk) = Paillier::keypair().keys();
    let (bob_ek, _bob_dk) = Paillier::keypair().keys();

    // Encrypt Alice and Bob's shared secrets with their respective Paillier public keys
    let alice_enc_secret = Paillier::encrypt(&alice_ek, alice_sk.into());
    let bob_enc_secret = Paillier::encrypt(&bob_ek, bob_sk.into());

    // Run MtA protocol
    //let a_i_times_b_j = mta_protocol(&alice_ek, &alice_enc_secret, &bob_pk.to_bigint().unwrap());
    //println!("{:?}", a_i_times_b_j);

    // For testing purposes, decrypt the result using Alice's secret key
    //let decrypted_result = signing::decrypt_point(a_i_times_b_j, &Scalar::from(alice_sk.into()));
    let beta_prime: u32 = OsRng.gen(); 

    // Verify the result
    //let actual_product = paillier::Mul::mul(&alice_sk, &paillier::EncodedCiphertext::from(alice_sk.into()), &paillier::EncodedCiphertext::from(b_j.into()));
    //let beta_prime_point = proj256_generator() * Scalar::from(beta_prime);
    //let expected_result = actual_product + beta_prime_point;


}
