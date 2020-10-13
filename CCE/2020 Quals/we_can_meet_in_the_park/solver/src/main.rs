use aes::block_cipher::generic_array::GenericArray;
use aes::block_cipher::{BlockCipher, NewBlockCipher};
use aes::Aes256;
use parking_lot::Mutex;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::process::exit;

static ENCRYPTED: &[u8; 48] = b"\xA5\xD1\xDB\x88\xFD\x34\xC6\x46\x0C\xF0\xC9\x55\x0F\xDB\x61\x9E\xB9\x17\xD7\x0B\xC8\x3D\xE5\x1B\x09\x71\xAE\x5F\x1C\xB5\xC7\x2C\xC5\x3F\x5A\xA7\xFB\xED\x63\xE6\xAD\x04\x0D\x16\xF6\x33\x16\x01";

pub enum Memo {
    First([u8; 4]),
    Second([u8; 4]),
}

fn aes_from_seed(seed: [u8; 4]) -> Aes256 {
    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let key = hasher.finalize();
    let key = GenericArray::from_slice(&key);

    Aes256::new(&key)
}

fn final_decryption(first_aes: &Aes256, second_aes: &Aes256) {
    let mut vec: Vec<u8> = Vec::new();
    for index in 0..3 {
        let mut buf = GenericArray::clone_from_slice(&ENCRYPTED[index * 16..(index + 1) * 16]);
        second_aes.decrypt_block(&mut buf);
        first_aes.decrypt_block(&mut buf);
        vec.extend_from_slice(buf.as_slice());
    }
    println!("{}", std::str::from_utf8(&vec).unwrap());

    exit(0);
}

fn main() {
    let middle: Mutex<HashMap<[u8; 16], Memo>> = Mutex::new(HashMap::new());

    for b0 in (0u8..100).rev() {
        println!("b0: {}", b0);
        (0u8..100).into_par_iter().for_each(|b1| {
            for b2 in 0u8..100 {
                for b3 in 0u8..100 {
                    let trying = [b0, b1, b2, b3];
                    let current_aes = aes_from_seed(trying);

                    let mut buf = GenericArray::clone_from_slice(b"___FLAGHEADER___");
                    current_aes.encrypt_block(&mut buf);
                    let buf_slice = buf.as_slice().try_into().unwrap();
                    if let Some(Memo::Second(second_key)) = middle.lock().get(buf_slice) {
                        let another_aes = aes_from_seed(*second_key);
                        final_decryption(&current_aes, &another_aes)
                    }
                    middle.lock().insert(*buf_slice, Memo::First(trying));

                    let mut buf = GenericArray::clone_from_slice(&ENCRYPTED[..16]);
                    current_aes.decrypt_block(&mut buf);
                    let buf_slice = buf.as_slice().try_into().unwrap();
                    if let Some(Memo::First(first_key)) = middle.lock().get(buf_slice) {
                        let another_aes = aes_from_seed(*first_key);
                        final_decryption(&another_aes, &current_aes)
                    }
                    middle.lock().insert(*buf_slice, Memo::Second(trying));
                }
            }
        });
    }
}
