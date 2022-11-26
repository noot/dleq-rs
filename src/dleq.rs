use crypto_bigint::{
    generic_array::GenericArray, rand_core::OsRng, ArrayEncoding, NonZero, RandomMod, UInt,
    Wrapping, U256,
};
use group::{GroupOps, ScalarMul};
use rand::{self, CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, Mul},
};

//use crate::range_proof::{Proof, generate_range_proof};

/// BITLEN_CHALLENGE represents the bitlength of the challenge.
const BITLEN_CHALLENGE: usize = 128;

// BITLEN_WITNESS represents the bitlength of the witness.
// Set to 64 as it's constrained by the maximum bit size of the range proof.
const BITLEN_WITNESS: usize = 64;

/// BITLEN_FAILURE represents the bitlength of the failure parameter.
/// Higher values mean the protocol is less likely to fail.
const BITLEN_FAILURE: usize = 60;

pub struct DLEqProver<Gp: DLEqGroup, Gq: DLEqGroup> {
    phantom_p: PhantomData<Gp>,
    phantom_q: PhantomData<Gq>,
}

#[allow(non_snake_case)]
pub struct DLEqProof<Gp: DLEqGroup, Gq: DLEqGroup> {
    //range_proof: Proof,
    pub Kp: Gp::GroupElement,
    pub Kq: Gq::GroupElement,

    pub z: U256,
    pub sp: <<Gp as DLEqGroup>::Field as DLEqField>::Scalar,
    pub sq: <<Gq as DLEqGroup>::Field as DLEqField>::Scalar,

    pub Xp: Gp::GroupElement, // commitment xG + rH in Gp
    pub Xq: Gq::GroupElement, // commitment xG + rH in Gq
}

pub trait DLEqGroup {
    type GroupElement: Clone
        + Copy
        + Debug
        + Eq
        + Sized
        + Send
        + Sync
        + 'static
        + Add
        + GroupOps
        + ScalarMul<<Self::Field as DLEqField>::Scalar>;
    type Field: DLEqField;
    fn generator() -> Self::GroupElement;
    fn alt_generator() -> Self::GroupElement;
    fn to_be_bytes(_: Self::GroupElement) -> Vec<u8>;
}

pub trait DLEqField {
    type Scalar: Copy + Debug + Sized + Eq + Add<Output = Self::Scalar> + Mul<Output = Self::Scalar>;
    fn to_be_bytes(_: &Self::Scalar) -> Vec<u8>;
    fn from_be_bytes(_: &[u8]) -> Self::Scalar;
    fn random<R: CryptoRng + RngCore>(_: R) -> Self::Scalar;
}

fn chunkify(v: &[u8; 32]) -> [[u8; 8]; 4] {
    let mut res = [[0u8; 8]; 4];
    for i in 0..4 {
        res[i].copy_from_slice(&v[i * 8..(i + 1) * 8]);
    }
    res
}

#[allow(non_snake_case)]
struct DLEqProofIntermediate<Gp: DLEqGroup, Gq: DLEqGroup> {
    pub k: U256,

    pub Kp: Gp::GroupElement, // kG + tH
    pub Kq: Gq::GroupElement, // kG + tH

    pub Xp: Gp::GroupElement, // commitment xG + rH in Gp
    pub Xq: Gq::GroupElement, // commitment xG + rH in Gq

    pub tp: <<Gp as DLEqGroup>::Field as DLEqField>::Scalar,
    pub tq: <<Gq as DLEqGroup>::Field as DLEqField>::Scalar,

    pub rp: <<Gp as DLEqGroup>::Field as DLEqField>::Scalar,
    pub rq: <<Gq as DLEqGroup>::Field as DLEqField>::Scalar,

    pub z: U256,
}

impl<Gp: DLEqGroup, Gq: DLEqGroup> DLEqProver<Gp, Gq> {
    pub fn new() -> DLEqProver<Gp, Gq> {
        DLEqProver::<Gp, Gq> {
            phantom_p: PhantomData,
            phantom_q: PhantomData,
        }
    }

    pub fn prove_private_key(&self, x: &[u8; 32]) -> Vec<DLEqProof<Gp, Gq>> {
        self.prove_chunks(&chunkify(x))
    }

    #[allow(non_snake_case)]
    fn prove_chunks(&self, x_chunks: &[[u8; 8]; 4]) -> Vec<DLEqProof<Gp, Gq>> {
        let mut proofs = Vec::<DLEqProof<Gp, Gq>>::new();

        // part one: this is the part of the protocol up until and including challenge and `z` value calculation.
        let (intermediates, cp, cq) = loop {
            let mut intermediates = Vec::<DLEqProofIntermediate<Gp, Gq>>::new();

            for i in 0..4 {
                intermediates.push(self.proof_step_one(&x_chunks[i]));
            }

            // now generate c from all the intermediates, calculate z, and check it
            // this is kinda cursed, there's definitely a cleaner way to write this
            let Kps: Vec<<Gp as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Kp).collect();
            let Kp: <Gp as DLEqGroup>::GroupElement =
                Kps[1..].iter().fold(Kps[0], |acc, x| acc + *x);

            let Kqs: Vec<<Gq as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Kq).collect();
            let Kq: <Gq as DLEqGroup>::GroupElement =
                Kqs[1..].iter().fold(Kqs[0], |acc, x| acc + *x);

            let Xps: Vec<<Gp as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Xp).collect();
            let Xp: <Gp as DLEqGroup>::GroupElement =
                Xps[1..].iter().fold(Xps[0], |acc, x| acc + *x);

            let Xqs: Vec<<Gq as DLEqGroup>::GroupElement> =
                intermediates.iter().map(|i| i.Xq).collect();
            let Xq: <Gq as DLEqGroup>::GroupElement =
                Xqs[1..].iter().fold(Xqs[0], |acc, x| acc + *x);

            let c = challenge::<Gp, Gq>(Kp, Kq, Xp, Xq);

            let cp = Gp::Field::from_be_bytes(&c.to_be_byte_array());
            let cq = Gq::Field::from_be_bytes(&c.to_be_byte_array());

            // finally check all z values
            // if they're all ok, then break from the loop
            for i in 0..4 {
                let x_uint = U256::from_be_byte_array(*GenericArray::from_slice(&x_chunks[i]));
                let z = Wrapping(intermediates[i].k) + (Wrapping(c) * Wrapping(x_uint));
                let z = z.0;

                if check_z(&z) {
                    continue;
                }

                intermediates[i].z = z;
            }

            break (intermediates, cp, cq);
        };

        // part two: calculate s values and we're done!!
        for i in 0..4 {
            let sp = intermediates[i].tp + (cp * intermediates[i].rp);
            let sq = intermediates[i].tq + (cq * intermediates[i].rq);
            proofs.push(DLEqProof {
                //range_proof: generate_range_proof(x_uint, BITLEN_WITNESS),
                Kp: intermediates[i].Kp,
                Kq: intermediates[i].Kq,
                z: intermediates[i].z,
                sp: sp,
                sq: sq,
                Xp: intermediates[i].Xp,
                Xq: intermediates[i].Xq,
            })
        }

        proofs
    }

    #[allow(non_snake_case)]
    fn proof_step_one(&self, x: &[u8]) -> DLEqProofIntermediate<Gp, Gq> {
        // verify 0 < x < 2 ** BITLEN_WITNESS
        let x_uint = U256::from_be_byte_array(*GenericArray::from_slice(x));
        let upper_bound = NonZero::new(U256::ONE.shl_vartime(BITLEN_WITNESS)).unwrap();
        assert!(x_uint > U256::from(0u8) && x_uint < *upper_bound);

        let xp = Gp::Field::from_be_bytes(x);
        let xq = Gq::Field::from_be_bytes(x);

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

    #[allow(non_snake_case)]
    pub fn prove(&self, x: &[u8]) -> DLEqProof<Gp, Gq> {
        // verify 0 < x < 2 ** BITLEN_WITNESS
        let x_uint = U256::from_be_byte_array(*GenericArray::from_slice(x));
        let upper_bound = NonZero::new(U256::ONE.shl_vartime(BITLEN_WITNESS)).unwrap();
        assert!(x_uint > U256::from(0u8) && x_uint < *upper_bound);

        let xp = Gp::Field::from_be_bytes(x);
        let xq = Gq::Field::from_be_bytes(x);

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

        let (Kp, Kq, cp, cq, z) = loop {
            let k = U256::random_mod(&mut OsRng, &modulus);
            let k_bytes = k.to_be_byte_array();
            let kp = Gp::Field::from_be_bytes(&k_bytes);
            let kq = Gq::Field::from_be_bytes(&k_bytes);

            let Kp = (Gp::generator() * kp) + (Gp::alt_generator() * tp);
            let Kq = (Gq::generator() * kq) + (Gq::alt_generator() * tq);

            let c = challenge::<Gp, Gq>(Kp, Kq, Xp, Xq);

            let cp = Gp::Field::from_be_bytes(&c.to_be_byte_array());
            let cq = Gq::Field::from_be_bytes(&c.to_be_byte_array());

            let z = Wrapping(k) + (Wrapping(c) * Wrapping(x_uint));
            let z = z.0;

            if check_z(&z) {
                break (Kp, Kq, cp, cq, z);
            }
        };

        let sp = tp + (cp * rp);
        let sq = tq + (cq * rq);

        DLEqProof {
            //range_proof: generate_range_proof(x_uint, BITLEN_WITNESS),
            Kp: Kp,
            Kq: Kq,
            z: z,
            sp: sp,
            sq: sq,
            Xp: Xp,
            Xq: Xq,
        }
    }
}

impl<Gp: DLEqGroup, Gq: DLEqGroup> DLEqProof<Gp, Gq> {
    pub fn verify(&self) -> bool {
        // verify range proof
        // if !self.range_proof.verify() {
        //     return false;
        // }

        // recompute challenge
        let c = challenge::<Gp, Gq>(self.Kp, self.Kq, self.Xp, self.Xq);

        let cp = Gp::Field::from_be_bytes(&c.to_be_byte_array());
        let cq = Gq::Field::from_be_bytes(&c.to_be_byte_array());

        let zp = Gp::Field::from_be_bytes(&self.z.to_be_byte_array());
        let zq = Gq::Field::from_be_bytes(&self.z.to_be_byte_array());

        // 1. check Gp values
        let lhs = (Gp::generator() * zp) + (Gp::alt_generator() * self.sp);
        let rhs = self.Kp + (self.Xp * cp);
        if lhs != rhs {
            return false;
        }

        // 2. check Gq values
        let lhs = Gq::generator() * zq + Gq::alt_generator() * self.sq;
        let rhs = self.Kq + self.Xq * cq;
        if lhs != rhs {
            return false;
        }

        // 3. check z
        check_z(&self.z)
    }
}

#[allow(non_snake_case)]
fn challenge<Gp: DLEqGroup, Gq: DLEqGroup>(
    Kp: Gp::GroupElement,
    Kq: Gq::GroupElement,
    Xp: Gp::GroupElement,
    Xq: Gq::GroupElement,
) -> U256 {
    let mut hasher = Sha256::new();
    hasher.update(Gp::to_be_bytes(Gp::generator()));
    hasher.update(Gq::to_be_bytes(Gq::generator()));
    hasher.update(Gp::to_be_bytes(Gp::alt_generator()));
    hasher.update(Gq::to_be_bytes(Gq::alt_generator()));
    hasher.update(Gp::to_be_bytes(Kp));
    hasher.update(Gq::to_be_bytes(Kq));
    hasher.update(Gp::to_be_bytes(Xp));
    hasher.update(Gq::to_be_bytes(Xq));
    let res = hasher.finalize();

    let c_unreduced = U256::from_be_byte_array(res);
    let commitment_modulus = NonZero::new(U256::ONE.shl_vartime(BITLEN_CHALLENGE)).unwrap();
    c_unreduced % &commitment_modulus
}

// check_z returns true if z is between [2^(b_x+b_c), 2^(b_x+b_c+b_f)-1], false otherwise
fn check_z(z: &U256) -> bool {
    let one = U256::ONE;
    let pow_lower = BITLEN_CHALLENGE + BITLEN_WITNESS;
    let pow_upper = BITLEN_CHALLENGE + BITLEN_WITNESS + BITLEN_FAILURE;
    let lower: UInt<4> = one.shl_vartime(pow_lower);
    let upper: UInt<4> = one.shl_vartime(pow_upper);
    z >= &lower && z < &upper
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed25519::Ed25519Group, secp256k1::Secp256k1Group};

    use crypto_bigint::Encoding;

    #[test]
    fn dleq_prove_and_verify() {
        let modulus = NonZero::new(U256::ONE.shl_vartime(BITLEN_WITNESS)).unwrap();
        let x = U256::random_mod(&mut OsRng, &modulus);

        let prover = DLEqProver::<Ed25519Group, Secp256k1Group>::new();
        let proof = prover.prove(&x.to_be_bytes());
        assert!(proof.verify())
    }
}
