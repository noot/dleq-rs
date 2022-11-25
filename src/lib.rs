use ff::{Field, PrimeField};
use group::{Group, GroupOps, GroupOpsOwned, ScalarMul, ScalarMulOwned};
use num_bigint_dig::{RandBigInt, ToBigInt, ToBigUint};
use rand::{self, CryptoRng};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};

use elliptic_curve::generic_array::GenericArray;

/// BITLEN_CHALLENGE represents the bitlength of the challenge.
const BITLEN_CHALLENGE: usize = 128;

// BITLEN_WITNESS represents the bitlength of the witness.
const BITLEN_WITNESS: usize = 112;

/// BITLEN_FAILURE represents the bitlength of the failure parameter.
/// Higher values mean the protocol is less likely to fail.
const BITLEN_FAILURE: usize = 12;

pub struct DLEqProver<Gp: MyGroup, Gq: MyGroup> {
    phantom_p: PhantomData<Gp>,
    phantom_q: PhantomData<Gq>,
}

pub struct DLEqProof<Gp: MyGroup, Gq: MyGroup> {
    // TODO: add range proof
    pub Kp: Gp,
    pub Kq: Gq,
    // pub z: Gp::Scalar, // actually a scalar?
    // pub sp: Gp::Scalar,
    // pub sq: Gq::Scalar,
}

pub trait MyGroup:
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
    type Scalar: MyField;
    /// Basepoint
    fn generator() -> Self;
    /// Alt basepoint
    fn alt_generator() -> Self;
}

pub trait MyField:
    Sized + Eq + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Neg<Output = Self>
{
    fn from_be_bytes(_: &[u8]) -> Self;
    fn random<R: CryptoRng>(_: R) -> Self;
}

impl<Gp: MyGroup, Gq: MyGroup> DLEqProver<Gp, Gq> {
    pub fn new() -> DLEqProver<Gp, Gq> {
        DLEqProver::<Gp, Gq> {
            phantom_p: PhantomData,
            phantom_q: PhantomData,
        }
    }

    // x's type should be of the field with a smaller order.
    pub fn prove<P: PrimeField, F: Field>(x: &P) -> DLEqProof<Gp, Gq> {
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

        let Kp = Gp::generator() * kp + Gp::alt_generator() * tp;
        let Kq = Gq::generator() * kq + Gq::alt_generator() * tq;

        DLEqProof {
            Kp: Kp,
            Kq: Kq,
            // z: (),
            // sp: (),
            // sq: (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
