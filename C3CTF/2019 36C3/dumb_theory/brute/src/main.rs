use std::collections::{HashMap, HashSet};

use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};

const R: usize = 3;
const LIMIT: u32 = 65536;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
struct Block {
    block: [u32; R],
}

impl Block {
    fn half(self) -> Option<Self> {
        if (self.block[0] & 1) == 0 && (self.block[1] & 1) == 0 && (self.block[2] & 1) == 0 {
            Some(Block {
                block: [self.block[0] >> 1, self.block[1] >> 1, self.block[2] >> 1],
            })
        } else {
            None
        }
    }

    fn double(self) -> Option<Self> {
        if self.block[0] * 2 <= LIMIT && self.block[1] * 2 <= LIMIT && self.block[2] * 2 <= LIMIT {
            Some(Block {
                block: [self.block[0] * 2, self.block[1] * 2, self.block[2] * 2],
            })
        } else {
            None
        }
    }
}

fn sha256(bytes: &[u8]) -> Block {
    let mut hasher = Sha256::new();
    hasher.input(bytes);
    let buffer = hasher.result();
    Block {
        block: [
            (((buffer[0] as u32) << 8) | buffer[1] as u32) + 1,
            (((buffer[2] as u32) << 8) | buffer[3] as u32) + 1,
            (((buffer[4] as u32) << 8) | buffer[5] as u32) + 1,
        ],
    }
}

fn sha256_target(first: char, second: char) -> Block {
    sha256(
        format!(
            "Hello hxp! I would like the flag, please{} Thank you{}",
            first, second
        )
        .as_bytes(),
    )
}

// 32 characters, never generate "flag"
const ASCII: &[u8] = b"1234567890abcdefghijkABCDEFGHIJK";

fn main() {
    // sanity check, compare with python
    /*
    let block1 = sha256_target('바', '보');
    let block2 = sha256_target('a', 'b');
    let block3 = sha256_target('ú', 'C');

    println!("{:?}", &block1);
    println!("{:?}", &block2);
    println!("{:?}", &block3);

    block1.mul(block2);
    block1.mul(block3);
    block2.mul(block3);
    */

    let mut rng = &mut rand::thread_rng();

    let mut rand_history: HashMap<Block, String> = HashMap::new();
    let mut target_history: HashMap<Block, (char, char)> = HashMap::new();

    let mut rand_is_waiting_rand: HashSet<Block> = HashSet::new();
    let mut rand_is_waiting_target: HashSet<Block> = HashSet::new();
    let mut target_is_waiting_rand: HashSet<Block> = HashSet::new();

    let mut found_rand_rand = false;
    let mut found_rand_target = false;

    while !found_rand_rand || !found_rand_target {
        // fill buffer with random bytes
        let vec: Vec<u8> = ASCII.choose_multiple(&mut rng, 12).cloned().collect();
        let s1 = String::from_utf8(vec).unwrap();

        let current_hash = sha256(s1.as_bytes());
        if let Some(double) = current_hash.double() {
            rand_is_waiting_rand.insert(double);
            rand_is_waiting_target.insert(double);
        }
        if let Some(half) = current_hash.half() {
            rand_is_waiting_rand.insert(half);
            rand_is_waiting_target.insert(half);
        }

        // dbg!(&s1, &current_hash);

        if !found_rand_rand && rand_is_waiting_rand.get(&current_hash).is_some() {
            found_rand_rand = true;
            if let Some(double) = current_hash.double() {
                if let Some(s2) = rand_history.get(&double) {
                    println!("[+] Found rand-rand pair");
                    println!("s1: {}", &s1);
                    println!("s2: {}", &s2);
                    println!("H(s1): {:?}", &current_hash);
                    println!("H(s2): {:?}", &double);
                }
            }
            if let Some(half) = current_hash.half() {
                if let Some(s2) = rand_history.get(&half) {
                    println!("[+] Found rand-rand pair");
                    println!("s1: {}", &s1);
                    println!("s2: {}", &s2);
                    println!("H(s1): {:?}", &current_hash);
                    println!("H(s2): {:?}", &half);
                }
            }
        }

        if !found_rand_target && target_is_waiting_rand.get(&current_hash).is_some() {
            if let Some(double) = current_hash.double() {
                found_rand_target = true;
                let (c1, c2) = target_history.get(&double).unwrap();
                println!("[+] Found rand-target pair");
                println!("s1: {}", &s1);
                println!(
                    "s2: Hello hxp! I would like the flag, please{} Thank you{}",
                    c1, c2
                );
                println!("c1: {}, c2: {}", *c1 as u32, *c2 as u32);
                println!("H(s1): {:?}", &current_hash);
                println!("H(s2): {:?}", &double);
            }
        }

        rand_history.insert(current_hash, s1);

        let c1 = rand::random::<char>();
        let c2 = rand::random::<char>();

        let current_hash = sha256_target(c1, c2);
        if let Some(double) = current_hash.double() {
            target_is_waiting_rand.insert(double);
        }
        if let Some(half) = current_hash.half() {
            target_is_waiting_rand.insert(half);
        }

        // dbg!(&c1, &c2, &current_hash);

        if !found_rand_target && rand_is_waiting_target.get(&current_hash).is_some() {
            if let Some(half) = current_hash.half() {
                let s = rand_history.get(&half).unwrap();
                found_rand_target = true;
                println!("[+] Found target-rand pair");
                println!(
                    "s1: Hello hxp! I would like the flag, please{} Thank you{}",
                    c1, c2
                );
                println!("s2: {}", &s);
                println!("c1: {}, c2: {}", c1 as u32, c2 as u32);
                println!("H(s1): {:?}", &current_hash);
                println!("H(s2): {:?}", &half);
            }
        }

        target_history.insert(current_hash, (c1, c2));
    }
}
