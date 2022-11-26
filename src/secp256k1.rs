use group::{ff::PrimeField, GroupEncoding};
use hex_literal::hex;
use k256::{elliptic_curve::generic_array::GenericArray, *};
use rand::{CryptoRng, RngCore};

use crate::dleq::{DLEqField, DLEqGroup};

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Secp256k1Group;

pub struct Secp256k1Scalar;

impl DLEqGroup for Secp256k1Group {
    type GroupElement = k256::ProjectivePoint;
    type Field = Secp256k1Scalar;

    fn generator() -> Self::GroupElement {
        k256::ProjectivePoint::GENERATOR
    }

    fn alt_generator() -> Self::GroupElement {
        // https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
        ProjectivePoint::from_bytes(&GenericArray::from_slice(&hex!(
            "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        )))
        .unwrap()
    }

    fn to_be_bytes(p: Self::GroupElement) -> Vec<u8> {
        p.to_bytes().to_vec()
    }
}

impl DLEqField for Secp256k1Scalar {
    type Scalar = k256::Scalar;

    fn to_be_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_repr().to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Self::Scalar {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Scalar::from_repr(arr.into()).unwrap()
    }

    fn random<R: CryptoRng + RngCore>(mut r: R) -> Self::Scalar {
        let mut bytes = [0u8; 32];
        r.fill_bytes(&mut bytes);
        // clear top bit, in BE
        bytes[0] = bytes[0] >> 1;
        Scalar::from_repr(bytes.into()).unwrap()
    }
}
