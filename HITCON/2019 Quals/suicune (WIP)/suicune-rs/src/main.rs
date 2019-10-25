use std::env;
use std::process::exit;

const N: u64 = 0x5851F42D_4C957F2D;

struct Random {
    state: u64,
}

impl Random {
    fn new(seed: u64) -> Self {
        Random {
            state: N.wrapping_mul(seed).wrapping_add(N).wrapping_add(1),
        }
    }

    fn generate(&mut self) -> u32 {
        let a = self.state;
        let data = (((a ^ (a >> 18)) >> 27) as u32).rotate_right((a >> 59) as u32);
        self.state = N.wrapping_mul(self.state).wrapping_add(1);
        data
    }
}

fn build_table(key: u64, input_size: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut rand = Random::new(key);
    for _round in 0..16 {
        let mut state: Vec<_> = (0..=255u8).collect();
        for index in (2..=256).rev() {
            let remain = (std::u32::MAX - index + 1) % index;
            let cur_rand = if remain > 0 {
                let range = std::u32::MAX - remain + 1;
                let mut target = rand.generate();
                while target >= range {
                    target = rand.generate();
                }
                target
            } else {
                rand.generate()
            };
            state.swap((cur_rand % index) as usize, (index - 1) as usize);
        }
        rand.generate();
        rand.generate();
        let mut sliced = state[..input_size].to_vec();
        sliced.sort_by_key(|x| 255 - x);
        result.push(sliced.to_vec());
    }
    result
}

fn parse_enc_arg(args: &Vec<String>) -> Option<(u64, Vec<u8>)> {
    if args.len() < 4 {
        return None;
    }
    let plain = args[3].clone().into_bytes();
    match args[2].parse::<u64>() {
        Ok(key) => Some((key, plain)),
        _ => None,
    }
}

fn hex_digit_to_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("given byte is not ascii hexdigit"),
    }
}

fn parse_dec_arg(args: &Vec<String>) -> Option<(u64, Vec<u8>)> {
    if args.len() < 4 {
        return None;
    }

    let hex = &args[3];
    if hex.len() & 1 > 0 || !hex.as_bytes().iter().all(|char| char.is_ascii_hexdigit()) {
        return None;
    }
    let cipher: Vec<_> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|slice| (hex_digit_to_value(slice[0]) << 4) | hex_digit_to_value(slice[1]))
        .collect();

    match args[2].parse::<u64>() {
        Ok(key) => Some((key, cipher)),
        _ => None,
    }
}

fn parse_brute_arg(args: &Vec<String>) -> Option<(Vec<u8>)> {
    if args.len() < 3 {
        return None;
    }

    let hex = &args[2];
    if hex.len() & 1 > 0 || !hex.as_bytes().iter().all(|char| char.is_ascii_hexdigit()) {
        return None;
    }
    let cipher: Vec<_> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|slice| (hex_digit_to_value(slice[0]) << 4) | hex_digit_to_value(slice[1]))
        .collect();

    Some(cipher)
}

fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} [enc|dec|brute]", &args[0]);
        exit(1);
    }

    match args[1].as_str() {
        "enc" => {
            if let Some((key, mut current)) = parse_enc_arg(&args) {
                let txt_len = current.len();
                let table = build_table(key, txt_len);
                for round in 0..16 {
                    for i in 0..txt_len {
                        current[i] ^= table[round][i];
                    }
                    current.reverse();
                }
                for c in current.iter() {
                    print!("{:02x}", c);
                }
                println!("");
            } else {
                println!("Usage: {} enc key plain-text", &args[0]);
                exit(1);
            }
        }
        "dec" => {
            if let Some((key, mut current)) = parse_dec_arg(&args) {
                let txt_len = current.len();
                let table = build_table(key, txt_len);
                for round in (0..16).rev() {
                    current.reverse();
                    for i in 0..txt_len {
                        current[i] ^= table[round][i];
                    }
                }
                println!("{}", String::from_utf8_lossy(&current));
            } else {
                println!("Usage: {} dec key cipher-text", &args[0]);
                exit(1);
            }
        }
        "brute" => {
            if let Some(original) = parse_brute_arg(&args) {
                let txt_len = original.len();
                //for key in 0..65536 {
                for key in 0..65536 {
                    let mut current = original.clone();
                    let table = build_table(key, txt_len);
                    for round in (0..16).rev() {
                        current.reverse();
                        for i in 0..txt_len {
                            current[i] ^= table[round][i];
                        }
                    }
                    let num_printable = current.iter().filter(|&&c| 0x20 <= c && c <= 0x7E).count();
                    if num_printable >= 30 {
                        println!("{} - {}", key, String::from_utf8_lossy(&current));
                    }
                }
            } else {
                println!("Usage: {} brute cipher-text", &args[0]);
                exit(1);
            }
        }
        s => {
            eprintln!("Unknown command '{}'", s);
            println!("Usage: {} [enc|dec|brute]", &args[0]);
            exit(1);
        }
    }
}
