// use ff::{Field, PrimeField};
use group::{GroupOps, GroupOpsOwned, ScalarMul, ScalarMulOwned};
use num_bigint_dig::{BigUint, RandBigInt, ToBigUint};
use rand::{self, CryptoRng};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};

/// BITLEN_CHALLENGE represents the bitlength of the challenge.
const BITLEN_CHALLENGE: usize = 128;

// BITLEN_WITNESS represents the bitlength of the witness.
const BITLEN_WITNESS: usize = 112;

/// BITLEN_FAILURE represents the bitlength of the failure parameter.
/// Higher values mean the protocol is less likely to fail.
const BITLEN_FAILURE: usize = 12;

pub struct DLEqProver<Gp: DLEqGroup, Gq: DLEqGroup> {
    phantom_p: PhantomData<Gp>,
    phantom_q: PhantomData<Gq>,
}

pub struct DLEqProof<Gp: DLEqGroup, Gq: DLEqGroup> {
    // TODO: add range proof
    pub Kp: Gp,
    pub Kq: Gq,
    pub z: BigUint,
    pub sp: Gp::Scalar,
    pub sq: Gq::Scalar,
}

pub trait DLEqGroup:
    Clone
    + Copy
    + Eq
    + Sized
    + Send
    + Sync
    + 'static
    + Add
    + GroupOps
    + GroupOpsOwned
    + ScalarMul<Self::Scalar>
    + ScalarMulOwned<Self::Scalar>
{
    type Scalar: DLEqField;
    /// Basepoint
    fn generator() -> Self;
    /// Alt basepoint
    fn alt_generator() -> Self;
    fn to_bytes_be(&self) -> Vec<u8>;
}

pub trait DLEqField:
    Sized + Eq + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Neg<Output = Self>
{
    fn from_be_bytes(_: &[u8]) -> Self;
    fn random<R: CryptoRng>(_: R) -> Self;
}

impl<Gp: DLEqGroup, Gq: DLEqGroup> DLEqProver<Gp, Gq> {
    pub fn new() -> DLEqProver<Gp, Gq> {
        DLEqProver::<Gp, Gq> {
            phantom_p: PhantomData,
            phantom_q: PhantomData,
        }
    }

    pub fn prove(x: &[u8]) -> DLEqProof<Gp, Gq> {
        let one = 1_i32.to_biguint().unwrap();
        let two = 2_i32.to_biguint().unwrap();
        let pow = (BITLEN_CHALLENGE + BITLEN_WITNESS + BITLEN_FAILURE)
            .to_biguint()
            .unwrap();
        let k_max = two.modpow(&pow, &one); // this should be a bigint
        let mut rng = rand::thread_rng();
        let k_biguint = rng.gen_biguint_range(&one, &(&k_max - &one));

        let tp = Gp::Scalar::random(&mut rng);
        let tq = Gq::Scalar::random(&mut rng);

        let k = k_biguint.to_bytes_be();
        let kp = Gp::Scalar::from_be_bytes(&k);
        let kq = Gq::Scalar::from_be_bytes(&k);

        let Kp = Gp::generator() * kp + Gp::alt_generator() * &tp;
        let Kq = Gq::generator() * kq + Gq::alt_generator() * &tq;

        let xp = Gp::Scalar::from_be_bytes(x);
        let xq = Gq::Scalar::from_be_bytes(x);
        let Yp = Gp::generator() * &xp;
        let Yq = Gq::generator() * &xq;

        let mut hasher = Sha256::new();
        hasher.update(Gp::generator().to_bytes_be());
        hasher.update(Gq::generator().to_bytes_be());
        hasher.update(Gp::alt_generator().to_bytes_be());
        hasher.update(Gq::alt_generator().to_bytes_be());
        hasher.update(Kp.to_bytes_be());
        hasher.update(Kq.to_bytes_be());
        hasher.update(Yp.to_bytes_be());
        hasher.update(Yq.to_bytes_be());
        let res = hasher.finalize();

        let c_unreduced = BigUint::from_bytes_be(&res);
        let bitlen_commitment = BITLEN_CHALLENGE.to_biguint().unwrap();
        let commitment_modulus = two.modpow(&bitlen_commitment, &one);
        let c = c_unreduced.modpow(&one, &commitment_modulus);

        let x_biguint = BigUint::from_bytes_be(x);
        let z = k_biguint + &c * x_biguint;

        let cp = Gp::Scalar::from_be_bytes(&c.to_bytes_be());
        let cq = Gq::Scalar::from_be_bytes(&c.to_bytes_be());
        let sp = tp + cp * xp;
        let sq = tq + cq * xq;

        DLEqProof {
            Kp: Kp,
            Kq: Kq,
            z: z,
            sp: sp,
            sq: sq,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
