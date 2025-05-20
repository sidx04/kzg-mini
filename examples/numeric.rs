use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_std::{UniformRand, test_rng};
use kzg_mini::{KZGCeremony, Polynomial};

fn main() {
    let mut rng = test_rng();

    // Polynomial f(x) = 3x² + 2x + 1
    let poly = Polynomial::new(vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);

    let tau = Fr::rand(&mut rng);
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let setup = KZGCeremony::<Bls12_381>::setup(2, tau, g1, g2);

    let commitment = setup.commit(&poly);
    let point = Fr::from(42u64);
    let proof = setup.open(&poly, point);

    let ok = setup.verify(commitment, &proof);
    println!("Reference Polynomial: {:#?}", poly);
    println!("Commitment: {}", commitment);
    println!("Proof: {:#?}", proof);
    println!("KZG proof verified: {}", ok);
}
