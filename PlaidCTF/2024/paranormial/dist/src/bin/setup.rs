use paranormial::Setup;
use std::fs::File;

const DEGREE: usize = 256;

fn main() {
    let output_path = std::env::args().nth(1).expect("no output path given");
    let setup = Setup::rand(DEGREE);
    let f = File::create(output_path).unwrap();
    serde_json::to_writer(f, &setup).expect("error serializing setup");
}
