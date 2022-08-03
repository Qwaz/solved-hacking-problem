use std::fs;

use goblin::elf::{Elf, Reloc};

#[derive(Debug, PartialEq, Eq)]
enum MappedRelocType {
    Relative,
    Copy,
    Val64,
    Val32,
}

impl From<u32> for MappedRelocType {
    fn from(val: u32) -> Self {
        match val {
            8 => MappedRelocType::Relative,
            5 => MappedRelocType::Copy,
            1 => MappedRelocType::Val64,
            10 => MappedRelocType::Val32,
            v => panic!("Unknown reloc type {}", v),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NamedValue {
    Register(usize),
    R2Size,
    R3Name,
    R5ValShift,
    R7ValShift,
    Fail,
    Serial(usize),
    Sbox(usize),
    Out(usize),
    Value(i64),
}

impl From<i64> for NamedValue {
    fn from(value: i64) -> Self {
        match value {
            0x804084 => NamedValue::Register(1),
            0x80409c => NamedValue::Register(2),
            0x8040b4 => NamedValue::Register(3),
            0x8040cc => NamedValue::Register(4),
            0x8040e4 => NamedValue::Register(5),
            0x8040fc => NamedValue::Register(6),
            0x804114 => NamedValue::Register(7),
            0x8040a4 => NamedValue::R2Size,
            0x8040ac => NamedValue::R3Name,
            0x8040e7 => NamedValue::R5ValShift,
            0x804117 => NamedValue::R7ValShift,
            0x404060 => NamedValue::Fail,
            value => {
                const SERIAL: i64 = 0x404040;
                const SERIAL_END: i64 = 0x40405c;

                const SBOX: i64 = 0x8042BA;

                const OUT: i64 = 0x804aca;

                if SERIAL <= value && value < SERIAL_END {
                    NamedValue::Serial((value - SERIAL) as usize)
                } else if SBOX <= value && value < SBOX + 8 * 256 && (value - SBOX) % 8 == 0 {
                    NamedValue::Sbox(((value - SBOX) / 8) as usize)
                } else if OUT <= value && value < OUT + 24 {
                    NamedValue::Out((value - OUT) as usize)
                } else {
                    NamedValue::Value(value)
                }
            }
        }
    }
}

impl From<u64> for NamedValue {
    fn from(value: u64) -> Self {
        NamedValue::from(value as i64)
    }
}

impl std::fmt::Display for NamedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamedValue::Register(reg) => write!(f, "r{}", reg),
            NamedValue::R2Size => write!(f, "&r2.st_size"),
            NamedValue::R3Name => write!(f, "&r3.st_name"),
            NamedValue::R5ValShift => write!(f, "&r5.st_val+3"),
            NamedValue::R7ValShift => write!(f, "&r7.st_val+3"),
            NamedValue::Fail => write!(f, "&fail"),
            NamedValue::Serial(offset) => write!(f, "SERIAL[{}]", offset),
            NamedValue::Sbox(offset) => write!(f, "SBOX[{}]", offset),
            NamedValue::Out(offset) => write!(f, "OUT[{}]", offset),
            NamedValue::Value(addr) => write!(f, "{:x}", addr),
        }
    }
}

#[derive(Debug)]
enum Instruction {
    // Relative
    MovImm {
        out: NamedValue,
        value: NamedValue,
    },
    // Copy
    MovReg {
        out: NamedValue,
        reg: usize,
    },
    // Val64
    Add {
        out: NamedValue,
        reg: usize,
        value: NamedValue,
    },
    MemBuf,
    // Val32
    ModReg(usize),
}

impl Instruction {
    fn as_write_to_addr(&self, addr: usize) -> Option<i64> {
        match self {
            Instruction::MovImm {
                out,
                value: NamedValue::Value(value),
            } if out == &NamedValue::Value(addr as i64) => Some(*value),
            _ => None,
        }
    }
}

impl From<Reloc> for Instruction {
    fn from(reloc: Reloc) -> Self {
        let r_type = MappedRelocType::from(reloc.r_type);

        match r_type {
            MappedRelocType::Relative => {
                assert!(reloc.r_sym == 0);
                if reloc.r_offset == 0x804000 && reloc.r_addend == Some(0) {
                    Instruction::MemBuf
                } else {
                    Instruction::MovImm {
                        out: NamedValue::from(reloc.r_offset),
                        value: NamedValue::from(reloc.r_addend.unwrap()),
                    }
                }
            }
            MappedRelocType::Copy => {
                assert!(reloc.r_addend == Some(0));
                assert!(1 <= reloc.r_sym && reloc.r_sym <= 7);
                Instruction::MovReg {
                    out: NamedValue::from(reloc.r_offset),
                    reg: reloc.r_sym,
                }
            }
            MappedRelocType::Val64 => {
                assert!(1 <= reloc.r_sym && reloc.r_sym <= 7);
                Instruction::Add {
                    out: NamedValue::from(reloc.r_offset),
                    reg: reloc.r_sym,
                    value: NamedValue::from(reloc.r_addend.unwrap()),
                }
            }
            MappedRelocType::Val32 => {
                assert_eq!(reloc.r_addend, Some(0));
                assert_eq!(reloc.r_sym, 1);

                match reloc.r_offset {
                    0x8040cd => Instruction::ModReg(4),
                    0x8040fd => Instruction::ModReg(6),
                    offset => panic!("Unknown offset {:x}", offset),
                }
            }
        }
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Instruction::MovImm { out: addr, value } => write!(f, "{} = {}", addr, value),
            Instruction::MovReg { out: addr, reg } => write!(f, "{} = *r{}", addr, reg),
            Instruction::Add {
                out: addr,
                reg,
                value,
            } => {
                write!(f, "{} = r{} + {}", addr, reg, value)
            }
            Instruction::MemBuf => write!(f, "(buffer)"),
            Instruction::ModReg(reg) => write!(f, "r{} &= 0xff", reg),
        }
    }
}

const INSTRUCTION_SIZE: usize = 0x18;

fn check_reg_add(base: usize, instructions: &[Instruction], idx: usize) -> Option<usize> {
    if idx + 2 < instructions.len() {
        match (
            &instructions[idx],
            &instructions[idx + 1],
            &instructions[idx + 2],
        ) {
            (
                Instruction::MovReg { out: addr1, reg: 2 },
                Instruction::Add {
                    out,
                    reg,
                    value: NamedValue::Value(0),
                },
                Instruction::MovImm {
                    out: addr2,
                    value: NamedValue::Value(0),
                },
            ) => {
                if addr1 == addr2
                    && addr1
                        == &NamedValue::Value((base + INSTRUCTION_SIZE * (idx + 1) + 0x10) as i64)
                {
                    println!("{} = r{} + *r2", out, reg);
                    Some(3)
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    }
}

fn check_store(base: usize, instructions: &[Instruction], idx: usize) -> Option<usize> {
    if idx + 1 < instructions.len() {
        match (&instructions[idx], &instructions[idx + 1]) {
            (
                Instruction::MovReg { out: addr, reg: 2 },
                Instruction::Add {
                    out: NamedValue::Value(0),
                    reg,
                    value: NamedValue::Value(0),
                },
            ) => {
                if addr == &NamedValue::Value((base + INSTRUCTION_SIZE * (idx + 1)) as i64) {
                    println!("*r2 = r{}", reg);
                    Some(2)
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    }
}

fn check_buffer(base: usize, instructions: &[Instruction], idx: usize) -> Option<usize> {
    let start_addr = base + INSTRUCTION_SIZE * idx;

    let mut cur = idx;
    while cur < instructions.len() && matches!(instructions[cur], Instruction::MemBuf) {
        cur += 1;
    }

    if cur >= instructions.len() || instructions[cur].as_write_to_addr(start_addr).is_none() {
        return None;
    }

    println!("(buffer {:x})", start_addr);
    let mut expected_addr = start_addr;
    while cur < instructions.len() {
        if let Some(val) = instructions[cur].as_write_to_addr(expected_addr) {
            expected_addr += 8;
            cur += 1;
            for i in 0..8 {
                print!("{:02x}", (val >> (i * 8)) & 0xff);
            }
            print!("\n");
        } else {
            break;
        }
    }
    println!("(buffer end)");

    Some(cur - idx)
}

fn print_instructions(base: usize, instructions: &[Instruction]) {
    let mut idx = 0;
    while idx < instructions.len() {
        if let Some(step) = check_reg_add(base, instructions, idx)
            .or_else(|| check_store(base, instructions, idx))
            .or_else(|| check_buffer(base, instructions, idx))
        {
            idx += step;
        } else {
            println!("{}", instructions[idx]);
            idx += 1;
        }
    }
}

fn main() -> goblin::error::Result<()> {
    let buffer = fs::read("../eldar")?;
    let elf = Elf::parse(&buffer)?;

    println!("=== Instructions ===");
    let instructions = elf
        .dynrelas
        .iter()
        .skip(3)
        .map(|reloc| Instruction::from(reloc))
        .collect::<Vec<_>>();

    print_instructions(0x8042BA, &instructions);

    println!("=== Symbols ===");
    for symbol in &elf.dynsyms {
        // elf.dynstrtab.get_at(symbol.st_name).unwrap_or("<invalid>");
        println!("{:?}", symbol);
    }

    Ok(())
}
