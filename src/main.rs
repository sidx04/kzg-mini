use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_std::{UniformRand, test_rng};
use clap::Parser;
use kzg_mini::{KZGCeremony, Polynomial};
/// KZG CLI tool
#[derive(Parser, Debug)]
#[command(name = "kzg")]
#[command(about = "Commit to a string using KZG", long_about = None)]
struct Args {
    /// The input string
    #[arg(short, long)]
    input: String,
}

fn main() {
    let args = Args::parse();

    let poly = Polynomial::from_str(&args.input);

    let mut rng = test_rng();
    let tau = Fr::rand(&mut rng);
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let setup = KZGCeremony::<Bls12_381>::setup(poly.coeffs.len() - 1, tau, g1, g2);
    let commitment = setup.commit(&poly);

    let point = Fr::from(42u64);
    let proof = setup.open(&poly, point);

    let is_valid = setup.verify(commitment, &proof);

    println!("Input: {}", args.input);
    println!("Commitment: {:?}", commitment);
    println!("Verification passed? {}", is_valid);
}
