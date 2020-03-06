
extern crate zwaves_jni;
extern crate rand_core;
extern crate rand_xorshift;


use zwaves_jni::*;
use base64::{decode, encode};

use pairing::bls12_381::{*};
use pairing::{Engine};

use ff::{PrimeField, Field, PrimeFieldRepr};
use group::CurveProjective;

use zwaves_jni::verifier::{Proof};

use std::{mem, io, iter};
use std::io::{Read, Write};
use byteorder::{BigEndian, ReadBytesExt};

use zwaves_jni::serialization::{read_fr_repr_be, read_fr_vec};
use zwaves_jni::verifier::{TruncatedVerifyingKey, verify_proof};

use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::io::Cursor;
use serialization::write_fr_iter;



fn main() {

    const ninputs: usize=16;
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
        0xbc, 0xe5,
    ]);

    const SAMPLES: usize = 1000;

    let v = (0..SAMPLES).map(|_| {
        let vk = TruncatedVerifyingKey::<Bls12> {
            alpha_g1: G1::random(&mut rng).into_affine(),
            beta_g2: G2::random(&mut rng).into_affine(),
            gamma_g2: G2::random(&mut rng).into_affine(),
            delta_g2: G2::random(&mut rng).into_affine(),
            ic: (0..ninputs+1).map(|_| G1::random(&mut rng).into_affine() ).collect::<Vec<_>>()
        };
        let mut vk_buff = Cursor::new(Vec::<u8>::new());
        vk.write(&mut vk_buff).unwrap();

        let proof = Proof::<Bls12> {
            a: G1::random(&mut rng).into_affine(),
            b: G2::random(&mut rng).into_affine(),
            c: G1::random(&mut rng).into_affine()
        };
        let mut proof_buff = Cursor::new(Vec::<u8>::new());
        proof.write(&mut proof_buff).unwrap();

        let inputs = (0..ninputs).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
        let mut inputs_buff = vec![0u8; 32*ninputs];
        write_fr_iter(inputs.iter(), &mut inputs_buff).unwrap();
        (base64::encode(vk_buff.get_ref()), base64::encode(proof_buff.get_ref()), base64::encode(&inputs_buff))
    }).collect::<Vec<_>>();

    println!("{:?}", v);
}