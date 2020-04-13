
extern crate zwaves_jni;
extern crate rand_core;
extern crate rand_xorshift;


use zwaves_jni::*;
use base64::{decode, encode};

use pairing::bls12_381::{*};
use pairing::{Engine};

use ff::{PrimeField, Field, PrimeFieldRepr};
use group::{CurveProjective, CurveAffine};

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

    const ninputs: usize=1;
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
        0xbc, 0xe5,
    ]);

    const SAMPLES: usize = 1000;

    // let v = (0..SAMPLES).map(|_| {
    //     let vk = TruncatedVerifyingKey::<Bls12> {
    //         alpha_g1: G1::random(&mut rng).into_affine(),
    //         beta_g2: G2::random(&mut rng).into_affine(),
    //         gamma_g2: G2::random(&mut rng).into_affine(),
    //         delta_g2: G2::random(&mut rng).into_affine(),
    //         ic: (0..ninputs+1).map(|_| G1::random(&mut rng).into_affine() ).collect::<Vec<_>>()
    //     };
    //     let mut vk_buff = Cursor::new(Vec::<u8>::new());
    //     vk.write(&mut vk_buff).unwrap();

    //     let proof = Proof::<Bls12> {
    //         a: G1::random(&mut rng).into_affine(),
    //         b: G2::random(&mut rng).into_affine(),
    //         c: G1::random(&mut rng).into_affine()
    //     };
    //     let mut proof_buff = Cursor::new(Vec::<u8>::new());
    //     proof.write(&mut proof_buff).unwrap();

    //     let inputs = (0..ninputs).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
    //     let mut inputs_buff = vec![0u8; 32*ninputs];
    //     write_fr_iter(inputs.iter(), &mut inputs_buff).unwrap();
    //     (base64::encode(vk_buff.get_ref()), base64::encode(proof_buff.get_ref()), base64::encode(&inputs_buff))
    // }).collect::<Vec<_>>();

    let v = (0..SAMPLES).map(|_| {


        let inputs = (0..ninputs).map(|_| Fr::random(&mut rng)).collect::<Vec<_>>();
        let mut inputs_buff = vec![0u8; 32*ninputs];
        write_fr_iter(inputs.iter(), &mut inputs_buff).unwrap();

        let ic = (0..ninputs+1).map(|_| G1::random(&mut rng).into_affine() ).collect::<Vec<_>>();

        let mut x_sum = ic[0].into_projective();
        for i in 1..ninputs+1 {
            let mut t = ic[i].into_projective();
            t.mul_assign(inputs[i-1]);
            x_sum.add_assign(&t);
        }
        let g1_gen = x_sum.into_affine();
        let g2_gen = G2::random(&mut rng).into_affine();


        let a_1 = Fr::one();
        let a_2 = Fr::random(&mut rng);
        let a_3 = Fr::random(&mut rng);
        let b_1 = Fr::one();
        let b_2 = Fr::random(&mut rng);
        let b_3 = Fr::random(&mut rng);
        let b_4 = Fr::random(&mut rng);

        let mut a_4 = Fr::zero();
        let mut t = a_1;
        t.mul_assign(&b_1);
        a_4.add_assign(&t);
        t = a_2;
        t.mul_assign(&b_2);
        a_4.add_assign(&t);
        t = a_3;
        t.mul_assign(&b_3);
        a_4.add_assign(&t);
        a_4.mul_assign(&b_4.inverse().unwrap());




        let vk = TruncatedVerifyingKey::<Bls12> {
            alpha_g1: g1_gen.mul(a_3).into_affine(),
            beta_g2: g2_gen.mul(b_3).into_affine(),
            gamma_g2: g2_gen.clone(),
            delta_g2: g2_gen.mul(b_2).into_affine(),
            ic
        };
        let mut vk_buff = Cursor::new(Vec::<u8>::new());
        vk.write(&mut vk_buff).unwrap();

        let proof = Proof::<Bls12> {
            a: g1_gen.mul(a_4).into_affine(),
            b: g2_gen.mul(b_4).into_affine(),
            c: g1_gen.mul(a_2).into_affine()
        };
        let mut proof_buff = Cursor::new(Vec::<u8>::new());
        proof.write(&mut proof_buff).unwrap();

        //let res = crate::verifier::verify_proof(&vk, &proof, &inputs).unwrap_or(false);
        //assert!(res, "groth16_verify should be true");

        (base64::encode(vk_buff.get_ref()), base64::encode(proof_buff.get_ref()), base64::encode(&inputs_buff))
    }).collect::<Vec<_>>();

    println!("{:?}", v);
}