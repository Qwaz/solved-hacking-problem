#![feature(slice_patterns)]
#[macro_use]
extern crate lazy_static;
extern crate regex;

use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::num::ParseIntError;
use std::rc::Rc;
use std::str::FromStr;
use std::str::SplitWhitespace;
use std::usize;

#[derive(Debug)]
enum CompileError {
    TokenExpected,
    UnknownInstruction(String),
    UnknownLocation(String),
    MalformedInstruction(String),
    Parse(ParseIntError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CompileError::*;
        match *self {
            TokenExpected => write!(f, "expected more tokens"),
            UnknownInstruction(ref s) => write!(f, "unknown instruction '{}'", s),
            UnknownLocation(ref s) => write!(f, "unknown location '{}'", s),
            MalformedInstruction(ref s) => write!(f, "instruction is malformed, {}", s),
            Parse(ref e) => e.fmt(f),
        }
    }
}

impl Error for CompileError {
    fn description(&self) -> &str {
        use CompileError::*;
        match *self {
            TokenExpected => "expected more tokens",
            UnknownInstruction(_) => "unknown instruction",
            UnknownLocation(_) => "unknown location",
            MalformedInstruction(_) => "instruction is malformed",
            Parse(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        use CompileError::*;
        match *self {
            Parse(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<ParseIntError> for CompileError {
    fn from(err: ParseIntError) -> CompileError {
        CompileError::Parse(err)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Location {
    MagicValue(i32),
    EAX,
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    Stack(isize),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Data {
    Uninitialized,
    Value(i32),
}

#[derive(Debug, Clone, Copy)]
enum Instruction {
    MOVL,
    SUBL,
    ADDL,
    IMULL,
    XORL,
    ORL,
    ANDL,
    NOTL,
    LEAL,
}

#[derive(Debug, Clone)]
struct Command {
    line: usize,
    instruction: Instruction,
    locations: Vec<Location>,
}

#[derive(Debug)]
struct State {
    last_write: (Option<Command>, Vec<Rc<State>>),
    location: Location,
    value: Data,
}

#[derive(Debug)]
struct Simulation {
    value: i32,
    dependency: Vec<Rc<State>>,
    write_to: Location,
}

type Program = HashMap<Location, Rc<State>>;

fn get_state(program: &mut Program, location: Location) -> Rc<State> {
    program.entry(location).or_insert(Rc::new(State::empty(location))).clone()
}

impl Simulation {
    fn simulate(program: &mut Program, command: &Command) -> Result<Simulation, CompileError> {
        use Data::*;

        fn unary(states: Vec<Rc<State>>, f: &Fn(i32) -> i32) -> Result<Simulation, CompileError> {
            if let &[ref s1] = states.as_slice() {
                if let Value(v1) = s1.value {
                    return Ok(Simulation {
                        value: f(v1),
                        dependency: vec!(s1.clone()),
                        write_to: s1.location,
                    })
                }
            }
            Err(CompileError::MalformedInstruction("expected unary".to_string()))
        }

        fn binary_overwrite(states: Vec<Rc<State>>) -> Result<Simulation, CompileError> {
            if let &[ref s1, ref s2] = states.as_slice() {
                if let Value(v1) = s1.value {
                    return Ok(Simulation {
                        value: v1,
                        dependency: vec!(s1.clone()),
                        write_to: s2.location,
                    })
                }
            }
            Err(CompileError::MalformedInstruction("expected binary".to_string()))
        }

        fn binary_calculate(states: Vec<Rc<State>>, f: &Fn(i32, i32) -> i32) -> Result<Simulation, CompileError> {
            if let &[ref s1, ref s2] = states.as_slice() {
                if let (Value(v1), Value(v2)) = (s1.value, s2.value) {
                    return Ok(Simulation {
                        value: f(v1, v2),
                        dependency: vec!(s1.clone(), s2.clone()),
                        write_to: s2.location,
                    })
                }
            }
            Err(CompileError::MalformedInstruction("expected binary".to_string()))
        }

        fn ternary_calculate(states: Vec<Rc<State>>, f: &Fn(i32, i32) -> i32) -> Result<Simulation, CompileError> {
            if let &[ref s1, ref s2, ref s3] = states.as_slice() {
                if let (Value(v1), Value(v2)) = (s1.value, s2.value) {
                    return Ok(Simulation {
                        value: f(v1, v2),
                        dependency: vec!(s1.clone(), s2.clone()),
                        write_to: s3.location,
                    })
                }
            }
            Err(CompileError::MalformedInstruction("expected ternary".to_string()))
        }

        let states: Vec<_> =
            command.locations.iter().map(|l| get_state(program, *l)).collect();

        match command.instruction {
            Instruction::MOVL => binary_overwrite(states),
            Instruction::SUBL => binary_calculate(states, &|a, b| a.overflowing_sub(b).0),
            Instruction::ADDL => binary_calculate(states, &|a, b| a.overflowing_add(b).0),
            Instruction::IMULL => match states.len() {
                2 => binary_calculate(states, &|a, b| a.overflowing_mul(b).0),
                3 => ternary_calculate(states, &|a, b| a.overflowing_mul(b).0),
                _ => Err(CompileError::MalformedInstruction("invalid imull".to_string())),
            },
            Instruction::XORL => binary_calculate(states, &|a, b| a ^ b),
            Instruction::ORL => binary_calculate(states, &|a, b| a | b),
            Instruction::ANDL => binary_calculate(states, &|a, b| a & b),
            Instruction::NOTL => unary(states, &|a| a ^ -1),
            Instruction::LEAL => ternary_calculate(states, &|a, b| a.overflowing_add(b).0),
        }
    }
}

impl Location {
    fn parse_locations<'a>(kind: Instruction, token: &'a mut SplitWhitespace) -> Result<Vec<Location>, CompileError> {
        use Location::*;

        lazy_static! {
            static ref STACK_PATTERN: Regex = Regex::new(r"(-?\d+)\(%rbp\)").unwrap();
            static ref LEAL_ASSEMBLY_PATTERN: Regex = Regex::new(r"\(([^,]+),([^)]+)\)").unwrap();
            static ref LEAL_IMMEDIATE_PATTERN: Regex = Regex::new(r"(-?\d+)\(([^)]+)\)").unwrap();
        }

        fn parse_assembly(s: &str) -> Result<Location, CompileError> {
            match s {
                "%eax" => Ok(EAX),
                "%ebx" => Ok(EBX),
                "%ecx" => Ok(ECX),
                "%edx" => Ok(EDX),
                "%esi" => Ok(ESI),
                "%edi" => Ok(EDI),
                "%rax" => Ok(EAX),
                "%rbx" => Ok(EBX),
                "%rcx" => Ok(ECX),
                "%rdx" => Ok(EDX),
                "%rsi" => Ok(ESI),
                "%rdi" => Ok(EDI),
                _ => Err(CompileError::UnknownLocation(s.to_string())),
            }
        }

        fn parse_general(s: &str) -> Result<Location, CompileError> {
            let s = if s.ends_with(',') {&s[..s.len()-1]} else {s};

            if s.starts_with('$') {
                return Ok(MagicValue((&s[1..]).parse()?))
            }

            if let Some(capture) = STACK_PATTERN.captures(s) {
                return Ok(Stack(capture.get(1).unwrap().as_str().parse()?))
            }

            parse_assembly(s)
        }

        fn parse_leal(s: &str) -> Result<Vec<Location>, CompileError> {
            if let Some(capture) = LEAL_ASSEMBLY_PATTERN.captures(s) {
                return Ok(vec!(
                    parse_assembly(capture.get(1).unwrap().as_str())?,
                    parse_assembly(capture.get(2).unwrap().as_str())?,
                ));
            }

            if let Some(capture) = LEAL_IMMEDIATE_PATTERN.captures(s) {
                return Ok(vec!(
                    MagicValue(capture.get(1).unwrap().as_str().parse()?),
                    parse_assembly(capture.get(2).unwrap().as_str())?,
                ));
            }

            Err(CompileError::MalformedInstruction("invalid leal".to_string()))
        }

        match kind {
            Instruction::LEAL => {
                let mut v = parse_leal(next_token(token)?)?;
                v.push(parse_assembly(next_token(token)?)?);
                Ok(v)
            },
            Instruction::IMULL => {
                let first_location = parse_general(next_token(token)?)?;

                let mut third_exist;
                let second_location = {
                    let s = next_token(token)?;
                    third_exist = s.ends_with(',');
                    parse_general(&s)?
                };
                if third_exist {
                    Ok(vec!(first_location, second_location, parse_general(next_token(token)?)?))
                } else {
                    Ok(vec!(first_location, second_location))
                }
            },
            Instruction::NOTL => Ok(vec!(parse_general(next_token(token)?)?)),
            _ => Ok(vec!(parse_general(next_token(token)?)?, parse_general(next_token(token)?)?))
        }
    }
}

impl FromStr for Instruction {
    type Err = CompileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Instruction::*;
        match s {
            "movl" => Ok(MOVL),
            "subl" => Ok(SUBL),
            "addl" => Ok(ADDL),
            "imull" => Ok(IMULL),
            "xorl" => Ok(XORL),
            "orl" => Ok(ORL),
            "andl" => Ok(ANDL),
            "notl" => Ok(NOTL),
            "leal" => Ok(LEAL),
            _ => Err(CompileError::UnknownInstruction(s.to_string())),
        }
    }
}

fn next_token<'a>(split: &'a mut SplitWhitespace) -> Result<&'a str, CompileError> {
    match split.next() {
        Some(s) => Ok(s),
        None => Err(CompileError::TokenExpected),
    }
}

impl FromStr for Command {
    type Err = CompileError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut split = line.split_whitespace();

        let line = next_token(&mut split)?.parse()?;
        let kind = next_token(&mut split)?.parse()?;

        Ok(Command {
            line,
            instruction: kind,
            locations: Location::parse_locations(kind, &mut split)?,
        })
    }
}

impl State {
    fn empty(location: Location) -> State {
        match location {
            Location::MagicValue(val) => State {
                last_write: (None, Vec::new()),
                location,
                value: Data::Value(val),
            },
            _ => State {
                last_write: (None, Vec::new()),
                location,
                value: Data::Uninitialized,
            }
        }
    }

    fn new(last_write: (Option<Command>, Vec<Rc<State>>), location: Location, value: Data) -> State {
        State {
            last_write,
            location,
            value,
        }
    }

    fn line(&self) -> Option<usize> {
        match self.last_write.0 {
            Some(ref command) => Some(command.line),
            None => None,
        }
    }
}

fn visit(cell: Rc<State>) -> HashSet<usize> {
    let mut visited = HashSet::new();
    let mut stack:Vec<Rc<State>> = Vec::new();

    if let Some(first_line) = cell.line() {
        visited.insert(first_line);
        stack.push(cell.clone());
        while let Some(cell) = stack.pop() {
            for dep in &cell.last_write.1 {
                if let Some(line) = dep.line() {
                    if !visited.contains(&line) {
                        visited.insert(line);
                        stack.push(dep.clone());
                    }
                }
            }
        }
    }

    visited
}

fn optimize(reader: &mut BufRead) -> Result<Vec<(usize, usize)>, CompileError> {
    // parse
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

    let last_line: Vec<_> = lines[lines.len()-1].split_whitespace().collect();
    let from: usize = last_line[0].parse()?;
    let to: usize = last_line[1].parse()?;

    let code = &lines[from-1..to];
    let commands: Result<Vec<Command>, _> = code.iter().map(|s| s.parse()).collect();
    let commands = commands?;

    // run
    let mut program = HashMap::new();

    use std::usize;
    let mut min = usize::MAX;
    let mut max = usize::MIN;

    for command in &commands {
        let simulation = Simulation::simulate(&mut program, command)?;
        let destination = get_state(&mut program, simulation.write_to);

        let new_value = Data::Value(simulation.value);
        let new_state = State::new(
            (Some(command.clone()), simulation.dependency),
            destination.location, new_value);

        program.insert(destination.location, Rc::new(new_state));

        min = min.min(command.line);
        max = max.max(command.line);
    }

    let visited: Vec<_> = visit(get_state(&mut program, Location::EAX)).into_iter().collect();
    let mut result = Vec::new();

    let mut last = usize::MIN;
    let mut adding = false;

    for i in min..max+1 {
        if visited.contains(&i) {
            if adding {
                result.push((last, i-1));
                last = usize::MIN;
                adding = false;
            }
        } else {
            if !adding {
                last = i;
                adding = true;
            }
        }
    }
    if adding {
        result.push((last, max));
    }

    Ok(result)
}

fn main() {
    let f = File::open("input.txt").expect("cannot open file");
    let mut reader = BufReader::new(f);

    match optimize(&mut reader) {
        Ok(result) => {
            for &(low, high) in &result {
                if low == high {
                    println!("{}", low);
                } else {
                    println!("{}-{}", low, high);
                }
            }
            println!("#");
        },
        Err(e) => println!("Error: {}", e),
    }
}
