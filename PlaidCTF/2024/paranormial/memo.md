secret = rand

G1 = [1, secret, secret^2, ..., secret^256] (in G1)
G2 = secret (in G2)

Polynomial

- evaluate

- commit

```rust
    pub fn commit(&self, setup: &Setup) -> G1Affine {
        let mut res = <G1Affine as GenericCurveAffine>::Projective::zero();
        for (coeff, b) in self.coefficients.iter().zip(setup.g1_basis.iter()) {
            let term = b.mul(*coeff);
            res.add_assign(&term);
        }
        res.into_affine()
    }
```

- divide

- prove

poly(x) = random polynomial
offset = flag - poly(ALPHA)
poly'(x) = poly(x) + offset = poly(x) + flag - poly(ALPHA)
