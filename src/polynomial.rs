use ark_ff::Field;
use ark_std::vec::Vec;
use std::string::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<F>
where
    F: Field,
{
    /// Represent a polynomial as: `coeffs[0]` + `coeffs[1]*x` + `coeffs[2]*x^2` + ...
    pub coeffs: Vec<F>,
}

impl<F> Polynomial<F>
where
    F: Field,
{
    /// Return a new polynomial from an array of `coeffs`.
    pub fn new(mut coeffs: Vec<F>) -> Self {
        while coeffs.last().is_some_and(|c| c.is_zero()) {
            coeffs.pop();
        }
        Polynomial {
            coeffs: coeffs.to_vec(),
        }
    }

    /// Zero polynomial
    pub fn zero() -> Self {
        Self { coeffs: vec![] }
    }

    /// Degree of the polynomial (0 if constant or zero)
    pub fn degree(&self) -> usize {
        if self.coeffs.is_empty() {
            0
        } else {
            self.coeffs.len() - 1
        }
    }

    /// Evaluate the polynomial at point `x` using Horner's method
    pub fn evaluate(&self, x: F) -> F {
        let mut result = F::zero();
        for coeff in self.coeffs.iter().rev() {
            result *= x;
            result += coeff;
        }
        result
    }

    /// Add two polynomials
    #[allow(clippy::needless_range_loop)]
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = vec![F::zero(); max_len];

        for i in 0..max_len {
            let a = self.coeffs.get(i).cloned().unwrap_or_else(F::zero);
            let b = other.coeffs.get(i).cloned().unwrap_or_else(F::zero);
            coeffs[i] = a + b;
        }

        Self::new(coeffs)
    }

    /// Multiply two polynomials (naive O(n^2) method)
    pub fn mul(&self, other: &Self) -> Self {
        if self.coeffs.is_empty() || other.coeffs.is_empty() {
            return Self::zero();
        }

        let mut coeffs = vec![F::zero(); self.degree() + other.degree() + 1];

        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                coeffs[i + j] += *a * *b;
            }
        }

        Self::new(coeffs)
    }

    /// Scale polynomial by a constant
    pub fn scale(&self, scalar: F) -> Self {
        let coeffs = self.coeffs.iter().map(|c| *c * scalar).collect();
        Self::new(coeffs)
    }

    /// Subtract another polynomial
    #[allow(clippy::needless_range_loop)]
    pub fn sub(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = vec![F::zero(); max_len];

        for i in 0..max_len {
            let a = self.coeffs.get(i).cloned().unwrap_or_else(F::zero);
            let b = other.coeffs.get(i).cloned().unwrap_or_else(F::zero);
            coeffs[i] = a - b;
        }

        Self::new(coeffs)
    }

    /// Divides self by (x - point), returns quotient polynomial.
    pub fn divide_by_linear(&self, a: F) -> (Self, F) {
        let n = self.coeffs.len();
        if n == 0 {
            return (Polynomial::new(vec![]), F::zero());
        }

        let mut quotient = vec![F::zero(); n - 1];
        let mut remainder = *self.coeffs.last().unwrap();

        // Work backwards from the highest degree
        for i in (0..n - 1).rev() {
            quotient[i] = remainder;
            remainder = self.coeffs[i] + a * remainder;
        }

        (Polynomial::new(quotient), remainder)
    }
}

impl<F: Field> std::str::FromStr for Polynomial<F> {
    type Err = ParseError;

    fn from_str(s: &str) -> ark_std::result::Result<Self, ParseError> {
        let coeffs: Vec<F> = s.bytes().map(|b| F::from(b as u64)).collect();
        Ok(Self::new(coeffs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn new_poly() {
        let c = vec![
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(0u64),
            Fr::from(1u64),
        ];

        let polynomial = Polynomial::new(c);
        println!("{:?}", polynomial);
    }

    #[test]
    fn add_poly() {
        let c = vec![
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(0u64),
            Fr::from(1u64),
        ];
        let d = vec![Fr::from(4u64), Fr::from(2u64), Fr::from(1u64)];

        let p1 = Polynomial::new(c);
        let p2 = Polynomial::new(d);

        let p_sum = p1.add(&p2);
        println!("{:?}", p_sum);
    }

    #[test]
    fn mul_poly() {
        let c = vec![
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(0u64),
            Fr::from(1u64),
        ];
        let d = vec![Fr::from(4u64), Fr::from(2u64), Fr::from(1u64)];

        let p1 = Polynomial::new(c);
        let p2 = Polynomial::new(d);

        let p_sum = p1.mul(&p2);
        println!("{:?}", p_sum);
    }

    #[test]
    fn div_poly() {
        // f(x) = 3x² + 5x + 7 ; a = 2
        // will return result of: f(x) / (x - 2)

        let coeffs = vec![Fr::from(7u64), Fr::from(5u64), Fr::from(3u64)];
        let poly = Polynomial::new(coeffs);
        let (q, _) = poly.divide_by_linear(Fr::from(2u64));

        println!("Quoitent: {:?}", q);
    }

    #[test]
    fn eval_poly() {
        // f(x) = x^3 + 2x + 3
        let c = vec![
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(0u64),
            Fr::from(1u64),
        ];

        let polynomial = Polynomial::new(c);

        let eval_poly = polynomial.evaluate(Fr::from(1)).to_string();

        assert_eq!(eval_poly, "6".to_string());
    }
}
