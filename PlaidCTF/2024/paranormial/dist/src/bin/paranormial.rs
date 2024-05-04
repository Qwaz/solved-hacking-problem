use pairing_ce::{
    bls12_381::{Fr, G1Affine},
    ff::{Field, PrimeField}, CurveAffine, GenericCurveProjective,
};
use paranormial::{Polynomial, Setup};
use primitive_types::U256;
use rand::{OsRng, Rng};
use std::{
    fs::File,
    io::Read,
};

const DEGREE: usize = 256;
const ALPHA: &str = "1337133713371337133713371337133713371337133713371337133713371337133713371337";

const NUM_POINTS: usize = 512;
const PARANOMIAL_RATE: u32 = 3;

fn main() {
    let setup_path = std::env::args().nth(1).expect("no output file given");
    let flag_path = std::env::args().nth(2).expect("no flag file given");
    let output_path = std::env::args().nth(3).expect("no output file given");

    let f = File::open(setup_path).unwrap();
    let setup: Setup = serde_json::from_reader(f).expect("error deserializing setup");
    let mut poly = Polynomial::rand(DEGREE);

    let mut f = File::open(flag_path).unwrap();
    let mut flag = [0u8; 32];
    f.read(&mut flag).expect("error reading flag file");

    let flag = U256::from_big_endian(&flag);
    let mut offset = Fr::from_str(&flag.to_string()).unwrap();

    let alpha = Fr::from_str(ALPHA).unwrap();
    offset.sub_assign(&poly.evaluate(alpha));
    poly.add_scalar(offset);

    let com = poly.commit(&setup);
    let f = File::create(output_path).unwrap();

    let mut values = Vec::with_capacity(NUM_POINTS);
    for i in 0..NUM_POINTS {
        let z = Fr::from_str(&i.to_string()).unwrap();
        let (mut y, mut proof) = poly.prove(&setup, z);

        let mut rng = OsRng::new().unwrap();
        if rng.gen_weighted_bool(PARANOMIAL_RATE) {
            println!("paranormial activity occured");
            y = rng.gen::<Fr>();
            proof = G1Affine::one().mul(rng.gen::<Fr>()).into_affine();
        }
        values.push((y, proof));
    }

    serde_json::to_writer(f, &(com, values)).expect("serialization failed");
}
