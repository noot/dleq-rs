use ff::{Field, PrimeField};
use group::Group;
use num_bigint_dig::{RandBigInt};
use rand;
use std::{marker::PhantomData};

/// BITLEN_CHALLENGE represents the bitlength of the challenge.
const BITLEN_CHALLENGE: usize = 128;

// BITLEN_WITNESS represents the bitlength of the witness.
const BITLEN_WITNESS: usize = 112;

/// BITLEN_FAILURE represents the bitlength of the failure parameter.
/// Higher values mean the protocol is less likely to fail.
const BITLEN_FAILURE: usize = 12;

pub struct DLEqProver<Gp: Group, Gq: Group> {
    phantom_p: PhantomData<Gp>,
    phantom_q: PhantomData<Gq>,
}

pub struct DLEqProof<Gp: Group, Gq: Group> {
    // TODO: add range proof
    pub Kp: Gp,
    pub Kq: Gq,
    // pub z: Gp::Scalar, // actually a scalar?
    // pub sp: Gp::Scalar,
    // pub sq: Gq::Scalar,
}

impl<Gp: Group, Gq: Group> DLEqProver<Gp, Gq> {
    pub fn new() -> DLEqProver<Gp, Gq> {
        DLEqProver::<Gp, Gq> {
            phantom_p: PhantomData,
            phantom_q: PhantomData,
        }
    }

    // x's type should be of the field with a smaller order.
    pub fn prove<P: PrimeField, F: Field>(x: &P) -> DLEqProof<Gp, Gq> {
        // let k: F;
        // // TODO: k is actually from 1..2^(sum of bitlens) - 1
        // if Gp::Scalar::NUM_BITS < Gq::Scalar::NUM_BITS {
        //     k = Gp::Scalar::random(r);
        // } else {
        //     k = Gq::Scalar::random(r);
        // }

        let k_max = 2 ** (BITLEN_CHALLENGE + BITLEN_WITNESS + BITLEN_FAILURE); // this should be a bigint
        let one = 1.to_biguint().unwrap();
        let mut rng = rand::thread_rng();
        let r = rng.gen_biguint_range(&one, &(&k_max - &one));

        let tp = Gp::Scalar::random(r);
        let tq = Gq::Scalar::random(r);

        DLEqProof {
            // Kp: (),
            // Kq: (),
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
