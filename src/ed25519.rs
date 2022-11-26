use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use hex_literal::hex;
use rand::{CryptoRng, RngCore};

use crate::dleq::{DLEqField, DLEqGroup};

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Ed25519Group;

pub struct Ed25519Scalar;

impl DLEqGroup for Ed25519Group {
    type GroupElement = EdwardsPoint;
    type Field = Ed25519Scalar;

    fn generator() -> Self::GroupElement {
        ED25519_BASEPOINT_POINT
    }

    fn alt_generator() -> Self::GroupElement {
        // https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
        CompressedEdwardsY(hex!(
            "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
        ))
        .decompress()
        .unwrap()
    }

    fn to_be_bytes(p: Self::GroupElement) -> Vec<u8> {
        p.compress().to_bytes().to_vec()
    }
}

impl DLEqField for Ed25519Scalar {
    type Scalar = Scalar;

    fn to_be_bytes(scalar: &Self::Scalar) -> Vec<u8> {
        // is this LE???
        let mut bytes = scalar.to_bytes().to_vec();
        bytes.reverse();
        bytes
    }

    fn from_be_bytes(bytes: &[u8]) -> Self::Scalar {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        arr.reverse();
        Scalar::from_canonical_bytes(arr.into()).unwrap()
    }

    fn random<R: CryptoRng + RngCore>(mut r: R) -> Self::Scalar {
        let mut bytes = [0u8; 64];
        r.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }
}
