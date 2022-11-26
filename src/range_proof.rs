// extern crate rand;
// use crypto_bigint::{U256, Encoding};

// extern crate curve25519_dalek;
// use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};

// extern crate merlin;
// use merlin::Transcript;

// extern crate bulletproofs;
// use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

// pub(crate) struct Proof {
//     proofs: [RangeProof, 4],
//     committed_values: [CompressedRistretto, 4],
// }

// pub(crate) fn generate_range_proof(x: U256) -> Proof {
//     let mut bytes = [0u8; 8];
//     bytes.copy_from_slice(&x.to_be_bytes()[24..32]);
//     let v = u64::from_be_bytes(bytes);

//     let pc_gens = PedersenGens::default();
//     let bp_gens = BulletproofGens::new(64, 1);

//     let blinding = Scalar::random(&mut rand::thread_rng());

//     let mut prover_transcript = Transcript::new(b"cross-group-DLEq");

//     let (proof, committed_value) = RangeProof::prove_single(
//         &bp_gens,
//         &pc_gens,
//         &mut prover_transcript,
//         v,
//         &blinding,
//         64,
//     ).unwrap();

//     Proof {
//         proof,
//         committed_value,
//     }
// }

// impl Proof {
//     pub(crate) fn verify(&self) -> bool {
//         let pc_gens = PedersenGens::default();
//         let bp_gens = BulletproofGens::new(64, 1);
//         let mut verifier_transcript = Transcript::new(b"cross-group-DLEq");

//         self.proof
//             .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &self.committed_value, 64)
//             .is_ok()
//     }
// }
