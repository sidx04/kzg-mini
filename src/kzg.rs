use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{One, PrimeField, Zero};

use crate::polynomial::Polynomial;

pub struct KZGCeremony<E>
where
    E: Pairing,
{
    pub powers_of_g: Vec<E::G1>,
    pub g2: E::G2,
    /// the secret acheived from the setup.
    pub g2_tau: E::G2,
    // /// `t` represents the degree of the polynomial used by the prover.
    // pub t: usize,
}

#[derive(Debug, Clone)]
pub struct KZGProof<E: Pairing> {
    pub point: E::ScalarField,
    pub value: E::ScalarField,
    pub proof: E::G1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZGCommitment<E: Pairing> {
    pub value: E::G1,
}

impl<E> KZGCeremony<E>
where
    E: Pairing,
{
    pub fn setup(t: usize, tau: E::ScalarField, g1: E::G1, g2: E::G2) -> Self {
        let mut pow_g = Vec::with_capacity(t + 1);
        let mut pow = E::ScalarField::one();
        for _ in 0..=t {
            pow_g.push(g1.mul_bigint(pow.into_bigint()));
            pow *= tau;
        }
        let g2_tau = g2.mul_bigint(tau.into_bigint());

        KZGCeremony {
            powers_of_g: pow_g,
            g2,
            g2_tau,
        }
    }

    pub fn commit(&self, poly: &Polynomial<E::ScalarField>) -> E::G1 {
        assert!(
            poly.coeffs.len() <= self.powers_of_g.len(),
            "Polynomial degree cannot exceed ceremony powers!"
        );

        let mut commitment = E::G1::zero();
        for (c, g) in poly.coeffs.iter().zip(self.powers_of_g.iter()) {
            commitment += g.mul_bigint(c.into_bigint());
        }

        commitment
    }

    pub fn open(&self, poly: &Polynomial<E::ScalarField>, point: E::ScalarField) -> KZGProof<E> {
        let value = poly.evaluate(point);

        // Construct p(x) - y
        let mut eval_poly = poly.clone();
        eval_poly.coeffs[0] -= value;

        // q(x) = (p(x) - y) / (x - point)
        let quotient = eval_poly.divide_by_linear(point).0;
        let proof = self.commit(&quotient);

        KZGProof {
            point,
            value,
            proof,
        }
    }

    pub fn verify(&self, commitment: E::G1, proof: &KZGProof<E>) -> bool {
        let g1 = E::G1::generator();
        let g2 = self.g2;

        // Left side: e(commitment - y * G1, g2)
        let rhs = E::pairing(commitment - g1.mul_bigint(proof.value.into_bigint()), g2);

        // Right side: e(proof, g2_tau - x * g2)
        let x = proof.point;
        let g2_tau_minus_xg2 = self.g2_tau - g2.mul_bigint(x.into_bigint());
        let lhs = E::pairing(proof.proof, g2_tau_minus_xg2);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_kzg_setup() {
        let mut rng = test_rng();

        // Degree of polynomial
        let t = 4;

        // Sample random tau from field
        let tau = Fr::rand(&mut rng);

        // Generators over the BLS12-381
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();

        // Run setup
        let ceremony = KZGCeremony::<Bls12_381>::setup(t, tau, g1, g2);

        // Check that we have t+1 powers
        assert_eq!(ceremony.powers_of_g.len(), t + 1);

        // Spot check: g.(tau^0) == g
        assert_eq!(ceremony.powers_of_g[0], g1);

        // g2_tau = g2.tau
        let expected_g2_tau = g2.mul_bigint(tau.into_bigint());
        assert_eq!(ceremony.g2_tau, expected_g2_tau);
    }

    #[test]
    fn test_kzg_commit() {
        let mut rng = test_rng();
        let t = 4;
        let tau = Fr::rand(&mut rng);

        let g1 = <Bls12_381 as Pairing>::G1::generator();
        let g2 = <Bls12_381 as Pairing>::G2::generator();

        let ceremony = KZGCeremony::<Bls12_381>::setup(t, tau, g1, g2);

        // Example polynomial: p(x) = 3 + 2x + x^2
        let poly = Polynomial {
            coeffs: vec![Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)],
        };

        let commitment = ceremony.commit(&poly);

        // Manual computation to verify:
        let mut expected = g1.mul_bigint(Fr::from(3u64).into_bigint());
        expected += ceremony.powers_of_g[1].mul_bigint(Fr::from(2u64).into_bigint());
        expected += ceremony.powers_of_g[2].mul_bigint(Fr::from(1u64).into_bigint());

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_kzg_open() {
        let mut rng = test_rng();
        let t = 3;
        let tau = Fr::rand(&mut rng);
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();

        let ceremony = KZGCeremony::<Bls12_381>::setup(t, tau, g1, g2);

        let poly = Polynomial {
            coeffs: vec![Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)], // 3 + 2x + x^2
        };

        let commitment = ceremony.commit(&poly);

        let point = Fr::from(10u64);
        let kzg_proof = ceremony.open(&poly, point);

        // Check evaluation is correct
        let expected_value =
            Fr::from(3u64) + Fr::from(2u64) * point + Fr::from(1u64) * point * point;
        assert_eq!(kzg_proof.value, expected_value);

        // Optionally: print to see output
        println!("Commitment: {:?}", commitment);
        println!("Point: {:?}", point);
        println!("Value: {:?}", kzg_proof.value);
        println!("Proof: {:?}", kzg_proof.point);
    }

    #[test]
    fn test_kzg_proof_verify() {
        let mut rng = test_rng();
        let tau = Fr::rand(&mut rng);

        let t = 3;
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();

        let ceremony = KZGCeremony::<Bls12_381>::setup(t, tau, g1, g2);

        let poly = Polynomial {
            coeffs: vec![Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)],
        };

        let commitment = ceremony.commit(&poly);

        let point = Fr::from(5u64);
        let proof = ceremony.open(&poly, point);

        let result = ceremony.verify(commitment, &proof);

        assert!(result, "KZG opening verification failed!");
    }
}
