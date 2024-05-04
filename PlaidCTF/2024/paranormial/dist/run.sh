#!/bin/bash

cargo run --release --bin setup setup.json
cargo run --release --bin paranormial setup.json flag.txt output.json
