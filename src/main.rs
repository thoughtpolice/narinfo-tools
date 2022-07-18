// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: © 2022 Austin Seipp

// ---------------------------------------------------------------------------------------------------------------------

use std::{env, io::Read};

use anyhow::Result;
use narinfo::{sk_to_keypair, sk_to_pk};

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
            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;

            let mut out = String::new();
            narinfo::narinfo_to_json(content, &mut out);
            println!("{}", out);
        }
        "sign" => {
            let store_dir = narinfo::Store::new(&env::var("NIX_STORE_DIR")?)?;
            let sk = env::var("NIX_SIGNING_KEY")?;
            let keys = sk_to_keypair(&sk)?;

            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;
            let body = content.trim();

            let sig = narinfo::sign_narinfo(&store_dir, &keys, body)?;
            let result = format!("{}\nSig: {}", body, sig);
            println!("{}", result);
        }
        "sk-to-pk" => {
            let sk = env::var("NIX_SIGNING_KEY")?;
            let pk = sk_to_pk(&sk)?;
            println!("{}", pk);
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
