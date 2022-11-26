extern crate rand;
use crypto_bigint::{Encoding, U64};

extern crate curve25519_dalek;
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

use crate::dleq::BITLEN_WITNESS;

pub(crate) struct Proof {
    proof: RangeProof,
    committed_value: CompressedRistretto,
}

pub(crate) fn generate_range_proof(x: &U64) -> Proof {
    let v = u64::from_be_bytes(x.to_be_bytes());

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let blinding = Scalar::random(&mut rand::thread_rng());

    let mut prover_transcript = Transcript::new(b"cross-group-DLEq");

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        v,
        &blinding,
        BITLEN_WITNESS,
    )
    .unwrap();

    Proof {
        proof,
        committed_value,
    }
}

impl Proof {
    pub(crate) fn verify(&self) -> bool {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut verifier_transcript = Transcript::new(b"cross-group-DLEq");

        self.proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &self.committed_value,
                64,
            )
            .is_ok()
    }
}
