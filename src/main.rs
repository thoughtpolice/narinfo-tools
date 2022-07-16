// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: © 2022 Austin Seipp

// ---------------------------------------------------------------------------------------------------------------------

use std::{env, io::Read};

use anyhow::Result;

mod narinfo;

extern crate wee_alloc;

// ---------------------------------------------------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [json] < ...", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    match mode.as_str() {
        "json" => {
            let mut out = String::new();
            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;
            narinfo::narinfo_to_json(content, &mut out);
            println!("{}", out);
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
