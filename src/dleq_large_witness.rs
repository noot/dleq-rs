use crypto_bigint::{
    generic_array::GenericArray, rand_core::OsRng, ArrayEncoding, NonZero, RandomMod, Wrapping,
    U256, U64,
};
use rand;

use crate::dleq::{
    challenge, check_z, DLEqField, DLEqGroup, DLEqProof, DLEqProver, BITLEN_CHALLENGE,
    BITLEN_FAILURE, BITLEN_WITNESS,
};
use crate::range_proof::generate_range_proof;

#[allow(non_snake_case)]
/// LargeWitnessDLEqProof is a proof for a witness with bitlength > BITLEN_WITNESS.
pub struct LargeWitnessDLEqProof<Gp: DLEqGroup, Gq: DLEqGroup> {
    /// commitment xG + rH in Gp
    pub Xp: Gp::GroupElement,
    /// commitment xG + rH in Gq
    pub Xq: Gq::GroupElement,

    proofs: Vec<DLEqProof<Gp, Gq>>,
}

#[allow(non_snake_case)]
struct DLEqProofIntermediate<Gp: DLEqGroup, Gq: DLEqGroup> {
    k: U256,

    Kp: Gp::GroupElement, // kG + tH
    Kq: Gq::GroupElement, // kG + tH

    Xp: Gp::GroupElement, // commitment xG + rH in Gp
    Xq: Gq::GroupElement, // commitment xG + rH in Gq

    tp: <<Gp as DLEqGroup>::Field as DLEqField>::Scalar,
    tq: <<Gq as DLEqGroup>::Field as DLEqField>::Scalar,

    rp: <<Gp as DLEqGroup>::Field as DLEqField>::Scalar,
    rq: <<Gq as DLEqGroup>::Field as DLEqField>::Scalar,

    z: U256,
}

impl<Gp: DLEqGroup, Gq: DLEqGroup> DLEqProver<Gp, Gq> {
    pub fn prove_large_witness(&self, x: &[u8; 32]) -> LargeWitnessDLEqProof<Gp, Gq> {
        // TODO: check that the witness isn't actually larger than min(order(Gp), order(Gq))
        self.prove_chunks(&chunkify(x))
    }

    #[allow(non_snake_case)]
    fn prove_chunks(&self, x_chunks: &[[u8; 8]; 4]) -> LargeWitnessDLEqProof<Gp, Gq> {
        let mut proofs = Vec::<DLEqProof<Gp, Gq>>::new();

        // part one: this is the part of the protocol up until and including challenge and `z` value calculation.
        let (intermediates, Xp, Xq, cp, cq) = loop {
            let mut intermediates = Vec::<DLEqProofIntermediate<Gp, Gq>>::new();

            for i in 0..4 {
                intermediates.push(self.proof_step_one(&x_chunks[i]));
            }

            // now generate c from all the intermediates, calculate z, and check it
            let Kps: Vec<<Gp as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Kp).collect();
            let Kqs: Vec<<Gq as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Kq).collect();
            let Xps: Vec<<Gp as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Xp).collect();
            let Xqs: Vec<<Gq as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Xq).collect();
            let (c, Xp, Xq) = challenge_from_many::<Gp, Gq>(Kps, Kqs, Xps, Xqs);

            let cp = Gp::Field::from_be_bytes(&c.to_be_byte_array());
            let cq = Gq::Field::from_be_bytes(&c.to_be_byte_array());

            // finally check all z values
            // if they're all ok, then break from the loop
            for i in 0..4 {
                let mut x_bytes = [0u8; 32];
                x_bytes[24..].copy_from_slice(&x_chunks[i]);
                let x_uint = U256::from_be_byte_array(*GenericArray::from_slice(&x_bytes));
                let z = Wrapping(intermediates[i].k) + (Wrapping(c) * Wrapping(x_uint));
                let z = z.0;

                if !check_z(&z) {
                    continue;
                }

                intermediates[i].z = z;
            }

            break (intermediates, Xp, Xq, cp, cq);
        };

        // part two: calculate s values and we're done!!
        for i in 0..4 {
            let sp = intermediates[i].tp + (cp * intermediates[i].rp);
            let sq = intermediates[i].tq + (cq * intermediates[i].rq);
            let x_uint = U64::from_be_byte_array(*GenericArray::from_slice(&x_chunks[i]));
            proofs.push(DLEqProof {
                range_proof: generate_range_proof(&x_uint),
                Kp: intermediates[i].Kp,
                Kq: intermediates[i].Kq,
                z: intermediates[i].z,
                sp: sp,
                sq: sq,
                Xp: intermediates[i].Xp,
                Xq: intermediates[i].Xq,
            })
        }

        LargeWitnessDLEqProof { proofs, Xp, Xq }
    }

    #[allow(non_snake_case)]
    fn proof_step_one(&self, x: &[u8]) -> DLEqProofIntermediate<Gp, Gq> {
        // verify 0 < x < 2 ** BITLEN_WITNESS
        let mut x_bytes = [0u8; 32];
        x_bytes[24..].copy_from_slice(&x);
        let x_uint = U256::from_be_byte_array(*GenericArray::from_slice(&x_bytes));
        let upper_bound = NonZero::new(U256::ONE.shl_vartime(BITLEN_WITNESS)).unwrap();
        assert!(x_uint > U256::from(0u8) && x_uint < *upper_bound);

        let xp = Gp::Field::from_be_bytes(&x_bytes);
        let xq = Gq::Field::from_be_bytes(&x_bytes);

        // calculate modulus for k value
        let pow = BITLEN_CHALLENGE + BITLEN_WITNESS + BITLEN_FAILURE;
        let modulus = NonZero::new(U256::ONE.shl_vartime(pow)).unwrap();
        let mut rng = rand::thread_rng();

        // random values
        let tp = Gp::Field::random(&mut rng);
        let tq = Gq::Field::random(&mut rng);
        let rp = Gp::Field::random(&mut rng);
        let rq = Gq::Field::random(&mut rng);

        // calculate commitments: xG + rH
        let Xp = (Gp::generator() * xp) + (Gp::alt_generator() * rp);
        let Xq = (Gq::generator() * xq) + (Gq::alt_generator() * rq);

        let k = U256::random_mod(&mut OsRng, &modulus);
        let k_bytes = k.to_be_byte_array();
        let kp = Gp::Field::from_be_bytes(&k_bytes);
        let kq = Gq::Field::from_be_bytes(&k_bytes);

        let Kp = (Gp::generator() * kp) + (Gp::alt_generator() * tp);
        let Kq = (Gq::generator() * kq) + (Gq::alt_generator() * tq);

        // z value is set in the caller.
        DLEqProofIntermediate {
            k,
            rp,
            rq,
            tp,
            tq,
            Kp,
            Kq,
            Xp,
            Xq,
            z: U256::ZERO,
        }
    }
}

impl<Gp: DLEqGroup, Gq: DLEqGroup> LargeWitnessDLEqProof<Gp, Gq> {
    #[allow(non_snake_case)]
    pub fn verify(&self) -> bool {
        // generate c from all the proofs, calculate z, and check it
        let Kps: Vec<<Gp as DLEqGroup>::GroupElement> = self.proofs.iter().map(|i| i.Kp).collect();
        let Kqs: Vec<<Gq as DLEqGroup>::GroupElement> = self.proofs.iter().map(|i| i.Kq).collect();
        let Xps: Vec<<Gp as DLEqGroup>::GroupElement> = self.proofs.iter().map(|i| i.Xp).collect();
        let Xqs: Vec<<Gq as DLEqGroup>::GroupElement> = self.proofs.iter().map(|i| i.Xq).collect();
        let (c, Xp, Xq) = challenge_from_many::<Gp, Gq>(Kps, Kqs, Xps, Xqs);

        // check that sub-commitments sum to main commitment
        if Xp != self.Xp || Xq != self.Xq {
            return false;
        }

        for proof in self.proofs.iter() {
            if !proof.verify_with_commitment(c) {
                return false;
            }
        }

        true
    }
}

#[allow(non_snake_case)]
fn challenge_from_many<Gp: DLEqGroup, Gq: DLEqGroup>(
    Kps: Vec<<Gp as DLEqGroup>::GroupElement>,
    Kqs: Vec<<Gq as DLEqGroup>::GroupElement>,
    Xps: Vec<<Gp as DLEqGroup>::GroupElement>,
    Xqs: Vec<<Gq as DLEqGroup>::GroupElement>,
) -> (U256, Gp::GroupElement, Gq::GroupElement) {
    let Kp: <Gp as DLEqGroup>::GroupElement = Kps[1..].iter().fold(Kps[0], |acc, x| acc + *x);

    let Kq: <Gq as DLEqGroup>::GroupElement = Kqs[1..].iter().fold(Kqs[0], |acc, x| acc + *x);

    let Xp: <Gp as DLEqGroup>::GroupElement = Xps[1..].iter().fold(Xps[0], |acc, x| acc + *x);

    let Xq: <Gq as DLEqGroup>::GroupElement = Xqs[1..].iter().fold(Xqs[0], |acc, x| acc + *x);

    (challenge::<Gp, Gq>(Kp, Kq, Xp, Xq), Xp, Xq)
}

fn chunkify(v: &[u8; 32]) -> [[u8; 8]; 4] {
    let mut res = [[0u8; 8]; 4];
    for i in 0..4 {
        res[i].copy_from_slice(&v[i * 8..(i + 1) * 8]);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed25519::Ed25519Group, secp256k1::Secp256k1Group};

    use rand::{self, RngCore};

    #[test]
    fn dleq_prove_and_verify_large_witness() {
        let mut x = [0u8; 32];
        let r = &mut rand::thread_rng();
        r.fill_bytes(&mut x);

        let prover = DLEqProver::<Ed25519Group, Secp256k1Group>::new();
        let proof = prover.prove_large_witness(&x);
        assert!(proof.verify());
    }
}
