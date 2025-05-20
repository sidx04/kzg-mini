# kzg-mini

A minimal, no-std compatible KZG polynomial commitment library for zk-SNARKs and cryptographic applications. Built on top of the `arkworks` ecosystem.

## 🧩 Features

- Define and operate on univariate polynomials over finite fields.
- Efficient polynomial arithmetic (add, sub, mul, scale, evaluate).
- Divide polynomials by linear factors.
- Minimal implementation of KZG commitments using a trusted setup.
- Fully generic over any pairing-friendly curve (`ark_ec::Pairing`).
- Suitable for educational, experimental, and constrained environments.

## 📦 Crate Status

> ⚠️ **Experimental**: This crate is designed for educational purposes. Not intended for production use.

## 🛠 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kzg-mini = "0.1"
ark-ff = "0.4"
ark-ec = "0.4"
ark-std = "0.4"
ark-bls12-381 = "0.4" # Or any curve from arkworks
```

## 🚀 Usage Examples

The following examples demonstrate how to create a polynomial commitment and open a KZG proof using the `kzg_mini` crate on the [BLS12-381](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://eprint.iacr.org/2019/403.pdf) curve. See [examples](https://github.com/sidx04/kzg-mini/tree/master/examples) for the full code.

### 1. Manually defined polynomial

This example constructs a polynomial `f(x) = 3x² + 2x + 1`, commits to it, and verifies a KZG proof:

```rust
fn main() {
    let mut rng = test_rng();

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
```

### 2. Polynomial from string

This example shows how to generate a polynomial from a string, commit to it, and verify the corresponding proof:

```rust
fn main() {
    let mut rng = test_rng();

    let poly = Polynomial::from_str("hell0, world!")?;

    let tau = Fr::rand(&mut rng);
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let setup = KZGCeremony::<Bls12_381>::setup(poly.coeffs.len(), tau, g1, g2);

    let commitment = setup.commit(&poly);
    let point = Fr::from(42u64);
    let proof = setup.open(&poly, point);

    let ok = setup.verify(commitment, &proof);
    println!("Reference Polynomial: {:#?}", poly);
    println!("Commitment: {}", commitment);
    println!("Proof: {:#?}", proof);
    println!("KZG proof verified: {}", ok);
}
```

## 🌉 Structure

- `Polynomial<F>`: A simple polynomial type over any `ark_ff::Field`, with arithmetic operations and evaluation.
- `KZGCeremony<E>`: Holds the trusted setup parameters for a KZG commitment over a pairing engine `E`.
- `KZGCommitment`, `KZGProof`: Types representing the output of commitment and opening.

## 🔐 Security

> This library uses a simplified version of KZG commitments for demonstration and learning. It **does not** use secure MPC for the trusted setup, so **do not use in production** as-is.

## 📄 License

MIT or Apache-2.0

## Acknowledgments

Built using [`arkworks`](https://github.com/arkworks-rs) libraries.
