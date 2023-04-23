use gennaro_rs::keygen::{Parameters, Party, keygen};

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
}
