use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crossbeam::thread;
use dashmap::DashMap;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};

const R: usize = 4;
const LIMIT: u32 = 65536;

/// this stores `value - 1` in the block
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
struct Block {
    block: [u16; R],
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block ({}, {}, {}, {})",
            self.block[0] as u32 + 1,
            self.block[1] as u32 + 1,
            self.block[2] as u32 + 1,
            self.block[3] as u32 + 1,
        )
    }
}

impl Block {
    fn half(self) -> Option<Self> {
        // check if all blocks are even
        if self.block.iter().all(|&x| (x & 1) == 1) {
            Some(Block {
                block: [
                    self.block[0] >> 1,
                    self.block[1] >> 1,
                    self.block[2] >> 1,
                    self.block[3] >> 1,
                ],
            })
        } else {
            None
        }
    }

    fn double(self) -> Option<Self> {
        // check if all blocks are in the range
        if self.block.iter().all(|&x| ((x as u32 * 2) + 1) < LIMIT) {
            Some(Block {
                block: [
                    self.block[0] * 2 + 1,
                    self.block[1] * 2 + 1,
                    self.block[2] * 2 + 1,
                    self.block[3] * 2 + 1,
                ],
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
            ((buffer[0] as u16) << 8) | buffer[1] as u16,
            ((buffer[2] as u16) << 8) | buffer[3] as u16,
            ((buffer[4] as u16) << 8) | buffer[5] as u16,
            ((buffer[6] as u16) << 8) | buffer[7] as u16,
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

trait AutoRelaxed {
    fn load_relax(&self) -> bool;
    fn store_relax(&self, val: bool);
}

impl AutoRelaxed for AtomicBool {
    fn load_relax(&self) -> bool {
        self.load(Ordering::Relaxed)
    }

    fn store_relax(&self, val: bool) {
        self.store(val, Ordering::Relaxed)
    }
}

fn print_rand_rand(s1: &str, s2: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "[+] Found rand-rand pair")?;
    writeln!(handle, "s1: {}", s1)?;
    writeln!(handle, "s2: {}", s2)?;
    writeln!(handle, "H(s1): {}", sha256(s1.as_bytes()))?;
    writeln!(handle, "H(s2): {}", sha256(s2.as_bytes()))?;
    Ok(())
}

fn print_rand_target(s1: &str, c1: char, c2: char) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "[+] Found rand-target pair")?;
    writeln!(handle, "s1: {}", &s1)?;
    writeln!(
        handle,
        "s2: Hello hxp! I would like the flag, please{} Thank you{}",
        c1, c2
    )?;
    writeln!(handle, "c1: {}, c2: {}", c1 as u32, c2 as u32)?;
    writeln!(handle, "H(s1): {}", sha256(s1.as_bytes()))?;
    writeln!(handle, "H(s2): {}", sha256_target(c1, c2))?;
    Ok(())
}

// a is not included; never generate "flag"
const ASCII: &[u8] =
    b"1234567890bcdefghijklmnopqrstuvwxyzBCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*_+-=~.?/,.;:<>{}[]";

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

    let rand_history: DashMap<Block, String> = DashMap::new();
    let target_history: DashMap<Block, (char, char)> = DashMap::new();

    let rand_is_waiting_rand: DashMap<Block, ()> = DashMap::new();
    let rand_is_waiting_target: DashMap<Block, ()> = DashMap::new();
    let target_is_waiting_rand: DashMap<Block, ()> = DashMap::new();

    let found_rand_rand = AtomicBool::new(false);
    let found_rand_target = AtomicBool::new(false);

    thread::scope(|s| {
        let rand_history = &rand_history;
        let target_history = &target_history;

        let rand_is_waiting_rand = &rand_is_waiting_rand;
        let rand_is_waiting_target = &rand_is_waiting_target;
        let target_is_waiting_rand = &target_is_waiting_rand;

        let found_rand_rand = &found_rand_rand;
        let found_rand_target = &found_rand_target;

        // Create a thread for each active CPU core.
        let core_ids = core_affinity::get_core_ids().unwrap();
        let handles = core_ids
            .into_iter()
            .map(|id| {
                s.spawn(move |_| {
                    let mut rng = &mut rand::thread_rng();

                    // Pin this thread to a single CPU core.
                    core_affinity::set_for_current(id);

                    while !found_rand_rand.load_relax() || !found_rand_target.load_relax() {
                        // fill buffer with random bytes
                        let vec: Vec<u8> = ASCII.choose_multiple(&mut rng, 10).cloned().collect();
                        let s1 = String::from_utf8(vec).unwrap();

                        let current_hash = sha256(s1.as_bytes());
                        if let Some(double) = current_hash.double() {
                            rand_is_waiting_rand.insert(double, ());
                            rand_is_waiting_target.insert(double, ());
                        }
                        if let Some(half) = current_hash.half() {
                            rand_is_waiting_rand.insert(half, ());
                            rand_is_waiting_target.insert(half, ());
                        }

                        // dbg!(&s1, &current_hash);

                        if !found_rand_rand.load_relax()
                            && rand_is_waiting_rand.get(&current_hash).is_some()
                        {
                            found_rand_rand.store_relax(true);
                            if let Some(double) = current_hash.double() {
                                if let Some(s2) = rand_history.get(&double) {
                                    print_rand_rand(&s1, s2.as_ref()).expect("printing error");
                                }
                            }
                            if let Some(half) = current_hash.half() {
                                if let Some(s2) = rand_history.get(&half) {
                                    print_rand_rand(&s1, s2.as_ref()).expect("printing error");
                                }
                            }
                        }

                        if !found_rand_target.load_relax()
                            && target_is_waiting_rand.get(&current_hash).is_some()
                        {
                            found_rand_target.store_relax(true);
                            if let Some(double) = current_hash.double() {
                                if let Some(pair) = target_history.get(&double) {
                                    let (c1, c2) = *pair;
                                    print_rand_target(&s1, c1, c2).expect("printing error");
                                }
                            }
                            if let Some(half) = current_hash.half() {
                                if let Some(pair) = target_history.get(&half) {
                                    let (c1, c2) = *pair;
                                    print_rand_target(&s1, c1, c2).expect("printing error");
                                }
                            }
                        }

                        rand_history.insert(current_hash, s1);

                        let c1 = rand::random::<char>();
                        let c2 = rand::random::<char>();

                        let current_hash = sha256_target(c1, c2);
                        if let Some(double) = current_hash.double() {
                            target_is_waiting_rand.insert(double, ());
                        }
                        if let Some(half) = current_hash.half() {
                            target_is_waiting_rand.insert(half, ());
                        }

                        // dbg!(&c1, &c2, &current_hash);

                        if !found_rand_target.load_relax()
                            && rand_is_waiting_target.get(&current_hash).is_some()
                        {
                            found_rand_target.store_relax(true);
                            if let Some(double) = current_hash.double() {
                                if let Some(s) = rand_history.get(&double) {
                                    print_rand_target(s.as_ref(), c1, c2).expect("printing error");
                                }
                            }
                            if let Some(half) = current_hash.half() {
                                if let Some(s) = rand_history.get(&half) {
                                    print_rand_target(s.as_ref(), c1, c2).expect("printing error");
                                }
                            }
                        }

                        target_history.insert(current_hash, (c1, c2));
                    }
                })
            })
            .collect::<Vec<_>>();

        for handle in handles.into_iter() {
            handle.join().unwrap();
        }
    })
    .unwrap();
}
