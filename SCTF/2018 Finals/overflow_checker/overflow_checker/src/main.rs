#![feature(box_patterns)]

extern crate glob;
extern crate pest;
#[macro_use]
extern crate pest_derive;

use glob::glob;

use std::env;
use std::fs;

mod parser;
mod program;
mod simulator;

use crate::simulator::State;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        let content = fs::read_to_string(&args[1]).expect("failed to open input file");
        let program = parser::parse_program(&content).expect("failed to parse test program");

        let result = simulator::run_block(&program, State::new());
        let result_str = match result {
            Ok(_) => "y",
            Err(()) => "n",
        };
        println!("{}", result_str);
    } else {for entry in glob("test/*.in").expect("glob pattern error") {
        let path = entry.unwrap();
        {
            let test_num = path.file_stem().unwrap();
            println!("Test {:?}", test_num);
        }

        let content = fs::read_to_string(path).expect("failed to read test input file");
        let program = parser::parse_program(&content).expect("failed to parse test program");

        let result = simulator::run_block(&program, State::new());
        let result_str = match result {
            Ok(_) => "y",
            Err(()) => "n",
        };
        println!("{}", result_str);
    }
    }
}
