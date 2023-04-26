use std::ops::Mul;

use k256::{elliptic_curve::Scalar, ProjectivePoint};
use paillier::{Encrypt, KeyGeneration, Paillier, Add, EncryptionKey, Keypair, DecryptionKey, Decrypt, Mul as PaillierMul, EncryptWithChosenRandomness};
use num_bigint::{BigInt, ToBigInt, Sign};
use num_traits::pow;
use textnonce::TextNonce;
use rug::Integer;
use paillier::{
    self,
    RawPlaintext, RawCiphertext, Randomness
};
use crate::{proj256_generator, generate_nonce};

pub type PartyIndex = u32;

pub struct SigningCommitment(ProjectivePoint);

pub struct Parameters {
    pub threshold: usize,
    pub num_parties: usize,
    pub paillier_modulus_bits: usize,
}

#[derive(Debug, Clone)]
pub struct Party {
    pub index: PartyIndex,
    pub public_key: Option<BigInt>,
    pub public_key_share: Option<BigInt>,
    pub encrypted_shared_secret: Option<EncryptionKey>,
}

pub struct PairwiseParties {
    party_i: Party,
    party_j: Party,
}

pub fn gen_nonce() -> textnonce::TextNonce {
    let nonce = TextNonce::new();
    nonce
}

pub fn commit() -> SigningCommitment {
    let k_i = generate_nonce();
    let r_i = generate_nonce();

    let g = proj256_generator();
    let h = proj256_generator();

    let g_to_ki = g.mul(k_i);
    let h_to_ri = h.mul(r_i);

    let ci = g_to_ki + h_to_ri;
    let commitment = ProjectivePoint::from(ci);
    SigningCommitment(commitment)
}


pub fn mta_protocol<'a>(
    alice_ek: &'a EncryptionKey,
    alice_c: &'a RawCiphertext<'a>,
    b: &'a Integer,
) -> RawCiphertext<'a> {
    let b_bn = b.clone();
    let b_times_enc_a = Paillier::mul(
        alice_ek,
        RawCiphertext::from(alice_c.clone()),
        RawPlaintext::from(&b_bn),
    );

    let beta_prim = Integer::from(paillier::Randomness::sample(&alice_ek));

    // E(beta_prim)
    let r = Randomness::sample(&alice_ek);
    let enc_beta_prim =
        Paillier::encrypt_with_chosen_randomness(alice_ek, RawPlaintext::from(&beta_prim), &r);

    let mta_out = Paillier::add(alice_ek, b_times_enc_a, enc_beta_prim);
    mta_out
}
