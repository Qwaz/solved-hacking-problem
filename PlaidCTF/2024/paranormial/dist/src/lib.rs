use pairing_ce::{
    bls12_381::{Fr, G1Affine, G2Affine},
    ff::Field,
    GenericCurveAffine, GenericCurveProjective,
};
use rand::{OsRng, Rng};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Setup {
    pub g1_basis: Vec<G1Affine>,
    pub g2_base: G2Affine,
}

impl Setup {
    pub fn new(degree: usize, secret: Fr) -> Self {
        let mut cur = G1Affine::one();
        let mut g1_basis = Vec::with_capacity(degree);
        for _ in 0..=degree {
            g1_basis.push(cur);
            cur = cur.mul(secret).into_affine();
        }
        let g2_base = G2Affine::one().mul(secret).into_affine();
        Self { g1_basis, g2_base }
    }

    pub fn rand(degree: usize) -> Self {
        let mut rng = OsRng::new().unwrap();
        let secret = rng.gen::<Fr>();
        Self::new(degree, secret)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Polynomial {
    coefficients: Vec<Fr>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<Fr>) -> Self {
        Polynomial { coefficients }
    }

    pub fn rand(degree: usize) -> Self {
        let mut rng = OsRng::new().unwrap();
        let coefficients = std::iter::from_fn(|| Some(rng.gen::<Fr>()))
            .take(degree)
            .collect();
        Polynomial { coefficients }
    }

    pub fn evaluate(&self, x: Fr) -> Fr {
        let mut res = Fr::zero();
        let mut cur = Fr::one();
        for coeff in self.coefficients.iter() {
            let mut term = cur;
            term.mul_assign(coeff);
            res.add_assign(&term);
            cur.mul_assign(&x);
        }
        res
    }

    pub fn commit(&self, setup: &Setup) -> G1Affine {
        let mut res = <G1Affine as GenericCurveAffine>::Projective::zero();
        for (coeff, b) in self.coefficients.iter().zip(setup.g1_basis.iter()) {
            let term = b.mul(*coeff);
            res.add_assign(&term);
        }
        res.into_affine()
    }

    pub fn add_scalar(&mut self, scalar: Fr) {
        self.coefficients[0].add_assign(&scalar)
    }

    pub fn divide(&self, divisor: &Self) -> Self {
        let mut dividend = self.coefficients.clone();
        let mut coefficients = vec![];

        let mut dividend_pos = dividend.len() - 1;
        let divisor_pos = divisor.coefficients.len() - 1;
        let mut difference = dividend_pos as isize - divisor_pos as isize;

        while difference >= 0 {
            let mut term_quotient = dividend[dividend_pos];
            term_quotient.mul_assign(
                &divisor.coefficients[divisor_pos]
                    .inverse()
                    .expect("zero encountered"),
            );
            coefficients.push(term_quotient);

            for i in (0..=divisor_pos).rev() {
                let difference = difference as usize;
                let mut y = divisor.coefficients[i];
                y.mul_assign(&term_quotient);
                let mut z = dividend[difference + i];
                z.sub_assign(&y);
                dividend[difference + i] = z;
            }

            dividend_pos -= 1;
            difference -= 1;
        }

        coefficients.reverse();
        Polynomial { coefficients }
    }

    pub fn prove(&self, setup: &Setup, z: Fr) -> (Fr, G1Affine) {
        let y = self.evaluate(z);
        let mut negz = z;
        negz.negate();
        let divisor = Self::new(vec![negz, Fr::one()]);
        let quo = self.divide(&divisor);
        let proof = quo.commit(setup);
        (y, proof)
    }
}
