use pairing::{Engine, PairingCurveAffine};
use group::{CurveProjective, CurveAffine, EncodedPoint};
use ff::{PrimeField, Field};

use std::io::{Read, Write};
use std::io;


#[derive(Debug)]
pub enum SynthesisError {
    /// During synthesis, we lacked knowledge of a variable assignment.
    AssignmentMissing,
    /// During synthesis, we divided by zero.
    DivisionByZero,
    /// During synthesis, we constructed an unsatisfiable constraint system.
    Unsatisfiable,
    /// During synthesis, our polynomials ended up being too high of degree
    PolynomialDegreeTooLarge,
    /// During proof generation, we encountered an identity in the CRS
    UnexpectedIdentity,
    /// During proof generation, we encountered an I/O error with the CRS
    IoError(io::Error),
    /// During verification, our verifying key was malformed.
    MalformedVerifyingKey,
    /// During CRS generation, we observed an unconstrained auxillary variable
    UnconstrainedVariable
}



#[derive(Clone)]
pub struct Proof<E: Engine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine
}



impl<E: Engine> PartialEq for Proof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a &&
        self.b == other.b &&
        self.c == other.c
    }
}

impl<E: Engine> Proof<E> {
    pub fn write<W: Write>(
        &self,
        mut writer: W
    ) -> io::Result<()>
    {
        writer.write_all(self.a.into_compressed().as_ref())?;
        writer.write_all(self.b.into_compressed().as_ref())?;
        writer.write_all(self.c.into_compressed().as_ref())?;

        Ok(())
    }

    pub fn read<R: Read>(
        mut reader: R
    ) -> io::Result<Self>
    {
        let mut g1_repr = <E::G1Affine as CurveAffine>::Compressed::empty();
        let mut g2_repr = <E::G2Affine as CurveAffine>::Compressed::empty();

        reader.read_exact(g1_repr.as_mut())?;
        let a = g1_repr
                .into_affine()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        reader.read_exact(g2_repr.as_mut())?;
        let b = g2_repr
                .into_affine()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        reader.read_exact(g1_repr.as_mut())?;
        let c = g1_repr
                .into_affine()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        Ok(Proof {
            a: a,
            b: b,
            c: c
        })
    }
}



#[derive(Clone)]
pub struct TruncatedVerifyingKey<E: Engine> {
    pub alpha_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    pub gamma_g2: E::G2Affine,
    pub delta_g2: E::G2Affine,
    pub ic: Vec<E::G1Affine>
}


impl<E: Engine> TruncatedVerifyingKey<E> {
    pub fn write<W: Write>(
        &self,
        mut writer: W
    ) -> io::Result<()>
    {
        writer.write_all(self.alpha_g1.into_compressed().as_ref())?;
        writer.write_all(self.beta_g2.into_compressed().as_ref())?;
        writer.write_all(self.gamma_g2.into_compressed().as_ref())?;
        writer.write_all(self.delta_g2.into_compressed().as_ref())?;
        for ic in &self.ic {
            writer.write_all(ic.into_compressed().as_ref())?;
        }
        Ok(())
    }

    pub fn read<R: Read>(
        mut reader: R
    ) -> io::Result<Self>
    {
        let mut g1_repr = <E::G1Affine as CurveAffine>::Compressed::empty();
        let mut g2_repr = <E::G2Affine as CurveAffine>::Compressed::empty();

        reader.read_exact(g1_repr.as_mut())?;
        let alpha_g1 = g1_repr
                .into_affine_unchecked()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        reader.read_exact(g2_repr.as_mut())?;
        let beta_g2 = g2_repr
                .into_affine_unchecked()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        reader.read_exact(g2_repr.as_mut())?;
        let gamma_g2 = g2_repr
                .into_affine_unchecked()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        reader.read_exact(g2_repr.as_mut())?;
        let delta_g2 = g2_repr
                .into_affine_unchecked()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        let mut ic = vec![];

        while reader.read_exact(g1_repr.as_mut()).is_ok() {
            let g1 = g1_repr
                    .into_affine_unchecked()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                    .and_then(|e| if e.is_zero() {
                        Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                    } else {
                        Ok(e)
                    })?;
            ic.push(g1);
        }

        Ok(TruncatedVerifyingKey {
            alpha_g1: alpha_g1,
            beta_g2: beta_g2,
            gamma_g2: gamma_g2,
            delta_g2: delta_g2,
            ic: ic.clone()
        })
    }
}


pub fn verify_proof<'a, E: Engine>(
    tvk: &'a TruncatedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr]
) -> Result<bool, SynthesisError>
{
    if (public_inputs.len() + 1) != tvk.ic.len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    let mut acc = tvk.ic[0].into_projective();

    for (i, b) in public_inputs.iter().zip(tvk.ic.iter().skip(1)) {
        acc.add_assign(&b.mul(i.into_repr()));
    }

    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // (-A) * B + alpha * beta + inputs * gamma + C * delta == 1

    let mut neg_a = proof.a.clone();
    neg_a.negate();

    Ok(E::final_exponentiation(
        &E::miller_loop(&[
            (&neg_a.prepare(), &proof.b.prepare()),
            (&tvk.alpha_g1.prepare(), &tvk.beta_g2.prepare()),
            (&acc.into_affine().prepare(), &tvk.gamma_g2.prepare()),
            (&proof.c.prepare(), &tvk.delta_g2.prepare())
        ])
    ).unwrap() == E::Fqk::one())
}
