use std::fs::File;

use pairing_ce::{
    bls12_381::{Bls12, Fr, G1Affine, G2Affine},
    ff::PrimeField,
    CurveAffine, Engine, GenericCurveProjective,
};
use paranormial::Setup;

const ALPHA: &str = "1337133713371337133713371337133713371337133713371337133713371337133713371337";

fn main() {
    let setup_path = "setup.json";
    let output_path = "output.json";

    let setup: Setup = serde_json::from_reader(File::open(setup_path).unwrap())
        .expect("error deserializing setup");
    let (commit, values): (G1Affine, Vec<(Fr, G1Affine)>) =
        serde_json::from_reader(File::open(output_path).unwrap())
            .expect("error deserializing output");

    for (i, (y, proof)) in values.into_iter().enumerate() {
        // Verify the evaluation result
        let x = Fr::from_str(&i.to_string()).unwrap();

        let mut commit_g1 = commit.into_projective();
        commit_g1.sub_assign(&G1Affine::one().mul(y));
        let mut proof_g2 = setup.g2_base.into_projective();
        proof_g2.sub_assign(&G2Affine::one().mul(x));
        let lhs = Bls12::pairing(proof, proof_g2.into_affine());
        let rhs = Bls12::pairing(commit_g1.into_affine(), G2Affine::one());

        if lhs == rhs {
            println!("{x}: {y}");
        }
    }

    let alpha = Fr::from_str(ALPHA).unwrap();
    println!("{alpha}");
}
