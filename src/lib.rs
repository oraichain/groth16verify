pub mod serialization;
pub mod verifier;

use std::io;

use pairing::bls12_381::{Bls12, Fr};

use crate::verifier::Proof;

use crate::serialization::read_fr_vec;
use crate::verifier::{verify_proof, TruncatedVerifyingKey};

pub fn groth16_verify(vk: &[u8], proof: &[u8], inputs: &[u8]) -> io::Result<u8> {
    let buff_vk_len = vk.len();
    let buff_proof_len = proof.len();
    let buff_inputs_len = inputs.len();

    if (buff_vk_len % 48 != 0) || (buff_inputs_len % 32 != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer length",
        ));
    }

    let inputs_len = buff_inputs_len / 32;

    if ((buff_vk_len / 48) != (inputs_len + 8)) || (buff_proof_len != 192) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer length",
        ));
    }

    let vk = TruncatedVerifyingKey::<Bls12>::read(vk)?;
    let proof = Proof::<Bls12>::read(proof)?;
    let inputs = read_fr_vec::<Fr>(inputs)?;

    if (inputs.len() != inputs_len) || (vk.ic.len() != (inputs_len + 1)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong buffer parsing",
        ));
    }

    Ok(verify_proof(&vk, &proof, inputs.as_slice())
        .map(|r| r as u8)
        .unwrap_or(0))
}

#[cfg(test)]
mod local_tests {
    use std::io::Cursor;

    use crate::serialization::write_fr_iter;

    use super::*;
    use base64::{decode, encode};
    use ff::Field;
    use group::{CurveAffine, CurveProjective};
    use pairing::bls12_381::{G1, G2};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaChaRng;
    use tiny_keccak::{Hasher, Sha3};

    fn gen_test_data() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let raw_inputs: [String; 2] = ["orai".to_string(), "1234567".to_string()];

        // simple hash, can use mmi20
        let inputs = raw_inputs.map(|input| {
            let mut sha3 = Sha3::v256();
            sha3.update(input.as_bytes());
            let mut output = [0u8; 32];
            sha3.finalize(&mut output);
            let mut rng = ChaChaRng::from_seed(output);
            Fr::random(&mut rng)
        });

        let mut inputs_buff = vec![0u8; 32 * inputs.len()];
        write_fr_iter(inputs.iter(), &mut inputs_buff).unwrap();

        let mut rng = thread_rng();

        let ic = (0..inputs.len() + 1)
            .map(|_| G1::random(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let mut x_sum = ic[0].into_projective();
        for i in 1..inputs.len() + 1 {
            let mut t = ic[i].into_projective();
            t.mul_assign(inputs[i - 1]);
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
            ic,
        };
        let mut vk_buff = Cursor::new(Vec::<u8>::new());
        vk.write(&mut vk_buff).unwrap();

        let proof = Proof::<Bls12> {
            a: g1_gen.mul(a_4).into_affine(),
            b: g2_gen.mul(b_4).into_affine(),
            c: g1_gen.mul(a_2).into_affine(),
        };
        let mut proof_buff = Cursor::new(Vec::<u8>::new());
        proof.write(&mut proof_buff).unwrap();

        (
            vk_buff.get_ref().to_vec(),
            proof_buff.get_ref().to_vec(),
            inputs_buff,
        )
    }

    #[test]
    fn test_groth16_verify_binaries_ok() {
        let (vk, proof, inputs) = gen_test_data();
        print!("vk :{}\n\ninput :{}\n\n", encode(&vk), encode(&inputs));
        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(res, "groth16_verify should be true");
    }

    #[test]
    fn test_groth16_verify_binaries_notok() {
        let vk = "hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r";
        let proof = "lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF";
        let inputs = "cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=";

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();

        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(!res, "groth16_verify should be false");
    }

    #[test]
    fn test_groth16_verify_binaries_bad_data() {
        let vk = "hwk883gUlTKCyXYA6XWZa8H9/xKIYZaJ0xEs0M5hQOMxiGpxocuX/8maSDmeCk3bo5ViaDBdO7ZBxAhLSe5k/5TFQyF5Lv7KN2tLKnwgoWMqB16OL8WdbePIwTCuPtJNAFKoTZylLDbSf02kckMcZQDPF9iGh+JC99Pio74vDpwTEjUx5tQ99gNQwxULtztsqDRsPnEvKvLmsxHt8LQVBkEBm2PBJFY+OXf1MNW021viDBpR10mX4WQ6zrsGL5L0GY4cwf4tlbh+Obit+LnN/SQTnREf8fPpdKZ1sa/ui3pGi8lMT6io4D7Ujlwx2RdCkBF+isfMf77HCEGsZANw0hSrO2FGg14Sl26xLAIohdaW8O7gEaag8JdVAZ3OVLd5Df1NkZBEr753Xb8WwaXsJjE7qxwINL1KdqA4+EiYW4edb7+a9bbBeOPtb67ZxmFqgyTNS/4obxahezNkjk00ytswsENg//Ee6dWBJZyLH+QGsaU2jO/W4WvRyZhmKKPdipOhiz4Rlrd2XYgsfHsfWf5v4GOTL+13ZB24dW1/m39n2woJ+v686fXbNW85XP/r";
        let proof = "lvQLU/KqgFhsLkt/5C/scqs7nWR+eYtyPdWiLVBux9GblT4AhHYMdCgwQfSJcudvsgV6fXoK+DUSRgJ++Nqt+Wvb7GlYlHpxCysQhz26TTu8Nyo7zpmVPH92+UYmbvbQCSvX2BhWtvkfHmqDVjmSIQ4RUMfeveA1KZbSf999NE4qKK8Do+8oXcmTM4LZVmh1rlyqznIdFXPN7x3pD4E0gb6/y69xtWMChv9654FMg05bAdueKt9uA4BEcAbpkdHF";
        let inputs = "cmzVCcRVnckw3QUPhmG4Bkppeg4K50oDQwQ9EH+Fq1s=";

        let vk = decode(vk).unwrap();
        let proof = decode(proof).unwrap();
        let inputs = decode(inputs).unwrap();

        let res = groth16_verify(&vk, &proof, &inputs[0..1]).unwrap_or(0) != 0;
        assert!(!res, "groth16_verify should be false");
    }
}
