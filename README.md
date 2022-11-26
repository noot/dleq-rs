# Cross-Group Discrete Logarithm Equality

This repo contains an implementation of Cross-Group DLEq proofs as specified [here](https://eprint.iacr.org/2022/1593.pdf). The protocol implemented is the non-interactive Fiat-Shamir'd version of the protocol described in the paper. Additionally, the extension in section 5 which allows for values larger than `BITLEN_WITNESS` to be proven.

This is not production-ready, I wrote this for learning purposes only. It has a lot of `unwraps()` :D 

## Usage

To generate a proof of a witness `0 < x < 2 ** 64`:

```rust
use crypto_bigint::U64;
use dleq-rs::{
    DLEqProver,
    ed25519::Ed25519Group, 
    secp256k1::Secp256k1Group,
};

let x = U64::random(&mut OsRng);
let prover = DLEqProver::<Ed25519Group, Secp256k1Group>::new();
let proof = prover.prove(&x.to_be_bytes());
assert!(proof.verify());
```

To generate a proof of a witness `0 < x < 2 ** 256`:

```rust
use crypto_bigint::U64;
use dleq-rs::{
    DLEqProver,
    ed25519::Ed25519Group, 
    secp256k1::Secp256k1Group,
};
use rand::{self, RngCore};

let mut x = [0u8; 32];
let r = &mut rand::thread_rng();
r.fill_bytes(&mut x);

let prover = DLEqProver::<Ed25519Group, Secp256k1Group>::new();
let proof = prover.prove_large_witness(&x);
assert!(proof.verify());
```