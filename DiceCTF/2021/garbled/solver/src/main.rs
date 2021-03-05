use once_cell::sync::Lazy;

type SBoxType = [[u32; 16]; 6];
type PBoxType = [u8; 24];

static S_BOX: SBoxType = [
    [15, 1, 7, 0, 9, 6, 2, 14, 11, 8, 5, 3, 12, 13, 4, 10],
    [3, 7, 8, 9, 11, 0, 15, 13, 4, 1, 10, 2, 14, 6, 12, 5],
    [4, 12, 9, 8, 5, 13, 11, 7, 6, 3, 10, 14, 15, 1, 2, 0],
    [2, 4, 10, 5, 7, 13, 1, 15, 0, 11, 3, 12, 14, 9, 8, 6],
    [3, 8, 0, 2, 13, 14, 5, 11, 9, 1, 7, 12, 4, 6, 10, 15],
    [14, 12, 7, 0, 11, 4, 13, 15, 10, 3, 8, 9, 2, 6, 1, 5],
];

static S_INV: SBoxType = [
    [3, 1, 6, 11, 14, 10, 5, 2, 9, 4, 15, 8, 12, 13, 7, 0],
    [5, 9, 11, 0, 8, 15, 13, 1, 2, 3, 10, 4, 14, 7, 12, 6],
    [15, 13, 14, 9, 0, 4, 8, 7, 3, 2, 10, 6, 1, 5, 11, 12],
    [8, 6, 0, 10, 1, 3, 15, 4, 14, 13, 2, 9, 11, 5, 12, 7],
    [2, 9, 3, 0, 12, 6, 13, 10, 1, 8, 14, 7, 11, 4, 5, 15],
    [3, 14, 12, 9, 5, 15, 13, 2, 10, 11, 8, 4, 1, 6, 0, 7],
];

static P_BOX: PBoxType = [
    13, 3, 15, 23, 6, 5, 22, 21, 19, 1, 18, 17, 20, 10, 7, 8, 12, 2, 16, 9, 14, 0, 11, 4,
];

static P_INV: PBoxType = [
    21, 9, 17, 1, 23, 5, 4, 14, 15, 19, 13, 22, 16, 0, 20, 2, 18, 11, 10, 8, 12, 7, 6, 3,
];

fn substitute(block: u32, s_box: &SBoxType) -> u32 {
    let mut output = 0;
    for i in 0..6 {
        output |= s_box[i][((block >> (4 * i)) & 0b1111) as usize] << (4 * i);
    }
    output
}

fn permute(block: u32, p_box: &PBoxType) -> u32 {
    let mut output = 0;
    for i in 0..24 {
        let bit = (block >> p_box[i]) & 1;
        output |= bit << i;
    }
    output
}

fn encrypt_data(mut block: u32, key: u32) -> u32 {
    for _ in 0..3 {
        block ^= key;
        block = substitute(block, &S_BOX);
        block = permute(block, &P_BOX);
    }
    block ^= key;
    block
}

fn decrypt_data(mut block: u32, key: u32) -> u32 {
    block ^= key;
    for _ in 0..3 {
        block = permute(block, &P_INV);
        block = substitute(block, &S_INV);
        block ^= key;
    }
    block
}

fn decrypt(data: u32, key1: u32, key2: u32) -> u32 {
    decrypt_data(decrypt_data(data, key2), key1)
}

struct GarbledGate {
    name: String,
    rows: [GarbledRow; 4],
}

struct GarbledRow {
    output: u32,
    validation: u32,
}

type LookupTable = Vec<Vec<u32>>;
type LookupTablePair = (LookupTable, LookupTable);

const MAX_BLOCK: u32 = 1 << 24;

fn create_lookup_table() -> LookupTable {
    let mut lookup_table = Vec::new();
    lookup_table.resize(MAX_BLOCK as usize, Vec::new());
    lookup_table
}

static INVERSE_KEY_LOOKUP: Lazy<Vec<Vec<u32>>> = Lazy::new(|| {
    let mut inverse_key_lookup = create_lookup_table();
    for key in 0..MAX_BLOCK {
        let enc = encrypt_data(0, key);
        inverse_key_lookup[enc as usize].push(key);
    }
    inverse_key_lookup
});

fn ungarble_row(row: &GarbledRow) -> LookupTablePair {
    let mut lookup_by_key0 = create_lookup_table();
    let mut lookup_by_key1 = create_lookup_table();

    for key1 in 0..MAX_BLOCK {
        let intermediate = decrypt_data(row.validation, key1);
        for &key0 in INVERSE_KEY_LOOKUP[intermediate as usize].iter() {
            lookup_by_key0[key0 as usize].push(key1);
            lookup_by_key1[key1 as usize].push(key0);
        }
    }

    (lookup_by_key0, lookup_by_key1)
}

fn print_row(row: &GarbledRow, key0: u32, key1: u32) {
    assert_eq!(decrypt(row.validation, key0, key1), 0);
    println!(
        "({}, {}) => {}",
        key0,
        key1,
        decrypt(row.output, key0, key1)
    );
}

fn test_row(gate: &GarbledGate, rows: &[LookupTablePair; 4], indices: [usize; 4]) {
    let row_ac = &rows[indices[0]];
    let row_ad = &rows[indices[1]];
    let row_bc = &rows[indices[2]];
    let row_bd = &rows[indices[3]];
    for a in 0..MAX_BLOCK {
        for &c in row_ac.0[a as usize].iter() {
            for &d in row_ad.0[a as usize].iter() {
                for &b1 in row_bc.1[c as usize].iter() {
                    for &b2 in row_bd.1[d as usize].iter() {
                        if b1 == b2 {
                            let mut outputs = Vec::new();
                            outputs.push(decrypt(gate.rows[indices[0]].output, a, c));
                            outputs.push(decrypt(gate.rows[indices[1]].output, a, d));
                            outputs.push(decrypt(gate.rows[indices[2]].output, b1, c));
                            outputs.push(decrypt(gate.rows[indices[3]].output, b1, d));

                            outputs.sort();
                            outputs.dedup();

                            if outputs.len() == 2 {
                                println!("Valid Combination Found");
                                print_row(&gate.rows[indices[0]], a, c);
                                print_row(&gate.rows[indices[1]], a, d);
                                print_row(&gate.rows[indices[2]], b1, c);
                                print_row(&gate.rows[indices[3]], b1, d);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn ungarble_gate(gate: &GarbledGate) {
    let rows = [
        ungarble_row(&gate.rows[0]),
        ungarble_row(&gate.rows[1]),
        ungarble_row(&gate.rows[2]),
        ungarble_row(&gate.rows[3]),
    ];

    test_row(gate, &rows, [0, 1, 2, 3]);
    test_row(gate, &rows, [0, 1, 3, 2]);
    test_row(gate, &rows, [0, 2, 1, 3]);
    test_row(gate, &rows, [0, 2, 3, 1]);
    test_row(gate, &rows, [0, 3, 1, 2]);
    test_row(gate, &rows, [0, 3, 2, 1]);
}

fn main() {
    let garbled_table = [
        GarbledGate {
            name: String::from("Gate 5"),
            rows: [
                GarbledRow {
                    output: 5737111,
                    validation: 2983937,
                },
                GarbledRow {
                    output: 15406556,
                    validation: 16284948,
                },
                GarbledRow {
                    output: 14172222,
                    validation: 14132908,
                },
                GarbledRow {
                    output: 4000971,
                    validation: 16383744,
                },
            ],
        },
        GarbledGate {
            name: String::from("Gate 6"),
            rows: [
                GarbledRow {
                    output: 8204186,
                    validation: 1546264,
                },
                GarbledRow {
                    output: 229766,
                    validation: 3208405,
                },
                GarbledRow {
                    output: 9550202,
                    validation: 13483954,
                },
                GarbledRow {
                    output: 13257058,
                    validation: 5195482,
                },
            ],
        },
        GarbledGate {
            name: String::from("Gate 7"),
            rows: [
                GarbledRow {
                    output: 1658768,
                    validation: 11512735,
                },
                GarbledRow {
                    output: 1023507,
                    validation: 9621913,
                },
                GarbledRow {
                    output: 7805976,
                    validation: 1206540,
                },
                GarbledRow {
                    output: 2769364,
                    validation: 9224729,
                },
            ],
        },
    ];

    for gate in garbled_table.iter() {
        println!("Ungarbling {}", &gate.name);
        ungarble_gate(gate);
    }
}
