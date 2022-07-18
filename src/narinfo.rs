// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: © 2022 Austin Seipp

//! Code for parsing and querying `narinfo` files.

// ---------------------------------------------------------------------------------------------------------------------

use std::collections::HashMap;
use std::fmt::Write;

use anyhow::{bail, Result};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};

// ---------------------------------------------------------------------------------------------------------------------

/// Parse an HTTP body containing a Nix `narinfo` file and produce a JSON
/// response. This is an extension to the primary Nix infrastructure, which
/// allows a bit easier querying.
pub fn narinfo_to_json(body: String, out: &mut String) {
    let mut prefix = "{";
    let mut sigs = HashMap::new();
    for x in body.lines() {
        let x = x.trim();
        if x == "" {
            continue;
        }
        let (k, v) = split_once(x);
        let (k, v) = (k.trim(), v.trim());

        // handle some special cases and emit them in a more appropriate JSON
        // equivalents.
        match k {
            // normal narinfo files
            "FileSize" | "NarSize" => {
                write!(out, "{} \"{}\": {}", prefix, k, v).unwrap();
            }
            "FileHash" | "NarHash" => {
                let (typ, hash) = split_once(v);

                write!(
                    out,
                    "{} \"{}\": {{ \"type\": \"{}\", \"hash\": \"{}\" }}",
                    prefix, k, typ, hash
                )
                .unwrap();
            }

            "References" => {
                let mut prefix2 = "[";
                let mut out2 = String::new();

                write!(out, "{} ", prefix).unwrap();
                for y in v.split_whitespace() {
                    write!(out2, "{} \"{}\"", prefix2, y).unwrap();
                    prefix2 = ",";
                }

                if prefix2 != "[" {
                    write!(out2, " ]").unwrap();
                }
                write!(out, "\"{}\": {}", k, out2).unwrap();
            }

            "Sig" => {
                // 'Sig' is the only key in a narinfo file that can occur
                // multiple times, vs something like 'References' which merely
                // contains multiple whitespace-separated entries. :| This is
                // seemingly just an afterthought/simple flaw, or something.
                //
                // While the official cache.nixos.org server may not at the
                // moment have any multi-signature narinfos, it possibly could
                // in the future. And any custom cache server could easily
                // return multiple signatures. Therefore, to handle this, we
                // have to iterate and collect all the signatures first, then
                // parse them.
                let (host, sig) = split_once(v);
                sigs.insert(host, sig);
            }

            // nix-cache-info
            "WantMassQuery" => {
                write!(
                    out,
                    "{} \"{}\": {}",
                    prefix,
                    k,
                    if v == "1" { "true" } else { "false" }
                )
                .unwrap();
            }
            "Priority" => {
                write!(out, "{} \"{}\": {}", prefix, k, v).unwrap();
            }

            _ => {
                write!(out, "{} \"{}\": \"{}\"", prefix, k, v).unwrap();
            }
        }

        prefix = ",";
    }

    if prefix != "{" {
        // there must have been at least one row

        if sigs.len() > 0 {
            write!(out, ", \"Sig\": ").unwrap();

            let mut prefix3 = "{";
            for (host, sig) in sigs.iter() {
                write!(out, "{} \"{}\": \"{}\"", prefix3, host, sig).unwrap();
                prefix3 = ",";
            }

            write!(out, " }}").unwrap();
        }

        write!(out, " }}\n").unwrap();
    }
}

/// Split a string containing *at least one* colon `:` character into two
/// strings at the first encounter.
///
/// Any remaining encounters are ignored and remain part of the second string.
/// The colon character is removed.
fn split_once(in_string: &str) -> (&str, &str) {
    let mut splitter = in_string.splitn(2, ':');
    let first = splitter.next().unwrap();
    let second = splitter.next().unwrap();
    (first, second)
}

// ---------------------------------------------------------------------------------------------------------------------

pub struct Keys<'a> {
    pub host: &'a str,
    pub keys: Keypair,
}

pub fn sk_to_keypair(sk: &str) -> Result<Keys> {
    let pieces: Vec<&str> = sk.split(":").collect();
    if pieces.len() != 2 {
        bail!("invalid sk: expected to contain hostname");
    }

    let host = pieces[0];
    let dat = pieces[1];

    let bin = base64::decode(dat)?;
    if bin.len() != 64 {
        bail!("Invalid secret key length");
    }

    return Ok(Keys {
        host,
        keys: Keypair {
            secret: SecretKey::from_bytes(&bin[0..32])?,
            public: PublicKey::from_bytes(&bin[32..])?,
        },
    });
}

pub fn sk_to_pk(sk: &str) -> Result<String> {
    let pieces: Vec<&str> = sk.split(":").collect();
    if pieces.len() != 2 {
        bail!("invalid sk: expected to contain hostname");
    }

    let kp = sk_to_keypair(sk)?;
    let pk = kp.keys.public.to_bytes();
    Ok(format!("{}:{}", kp.host, base64::encode(pk)))
}

pub fn sign_narinfo(store: &Store, ks: &Keys, body: &str) -> Result<String> {
    let mut ls = HashMap::new();
    for x in body.lines() {
        let x = x.trim();
        if x == "" {
            continue;
        }
        let (k, v) = split_once(x);
        let (k, v) = (k.trim(), v.trim());

        let accepted = vec!["StorePath", "NarHash", "NarSize", "References"];
        if !accepted.contains(&k) {
            continue;
        }
        ls.insert(k, v);
    }

    let path: &str = ls.get("StorePath").expect("no StorePath found");
    let hash: &str = ls.get("NarHash").expect("no NarHash found");
    let size: u64 = ls.get("NarSize").expect("no NarSize found").parse()?;
    let refs0: Vec<String> = ls
        .get("References")
        .expect("no References found")
        .split_whitespace()
        .map(|x| format!("{}/{}", store.store_path, x))
        .collect();
    // putting both of these in the same iteration causes capture errors which
    // i'm too inexperienced to solve gracefully, yet
    let refs: Vec<&str> = refs0.iter().map(|x| x.as_str()).collect();

    let fp = store.fingerprint_path(path, hash, &size, refs)?;
    let sig = base64::encode(ks.keys.sign(fp.as_bytes()).to_bytes());
    Ok(format!("{}:{}", ks.host, sig))
}

pub struct Store {
    store_path: String,
}

impl Store {
    pub fn new(store_path: &str) -> Result<Store> {
        Ok(Store {
            store_path: store_path.to_string(),
        })
    }

    pub fn fingerprint_path<'a, I>(
        &self,
        path: &str,
        hash: &str,
        size: &u64,
        refs: I,
    ) -> anyhow::Result<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        // https://github.com/NixOS/nix/blob/2.10.3/perl/lib/Nix/Manifest.pm#L234

        if !path.starts_with(&self.store_path) {
            bail!("path must start with store path");
        }

        if !hash.starts_with("sha256:") {
            bail!("hash must be sha256");
        }

        if hash.len() == 71 {
            // XXX FIXME: convert base16 to base32
            bail!("base16 hashes currently not supported");
        }

        if hash.len() != 59 {
            bail!("invalid hash length (not 59)");
        }

        let valid: Result<Vec<&'a str>, _> = refs
            .into_iter()
            .map(|p| {
                if !p.starts_with(&self.store_path) {
                    bail!("ref must start with store path");
                } else {
                    Ok(p)
                }
            })
            .collect();
        let refs = valid.unwrap().join(",");

        Ok(format!("1;{};{};{};{}", path, hash, size, refs))
    }
}

// ---------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::sk_to_keypair;
    use crate::narinfo::{sign_narinfo, sk_to_pk, Store};

    #[test]
    fn test_narinfo_to_json() {
        let input = r#"StorePath: /nix/store/dw2xrnys127khw71bjygg7hmny62243n-yosys-0.15
URL: nar/06yc663a4bsf4j76rwx97iz9lwy3fwmf8m2ck3in5bsyzvcyk0ds.nar.xz
Compression: xz
FileHash: sha256:06yc663a4bsf4j76rwx97iz9lwy3fwmf8m2ck3in5bsyzvcyk0ds
FileSize: 3542408
NarHash: sha256:1mpyzqm3s45jpp598aqnc6d8359zf83gb6j3zlm87vjwg5jdhhm3
NarSize: 17680416
References: 18fz9jnhmfkzkh6p1iwwwng4i7x4rag7-gcc-10.3.0-lib 20ix3np9v02ph8fwb2v41r5mzlfg8f73-libffi-3.4.2 9b9ryxskcwh573jwjz6m5l01whkcb39a-zlib-1.2.11 ab2ih3qiqkqjsapimxxyvzhxdwqcgyrn-tcl-8.6.11 dndi916j6yxzfzzj2sma2llhrlwahq06-bash-5.1-p16 dw2xrnys127khw71bjygg7hmny62243n-yosys-0.15 fsq9kj579dnfygb12zcagbn1sg8dnl6d-protobuf-3.19.3 hb1lzaisgx2m9n29hqhh6yp6hasplq1v-python3-3.9.10 klq81kinj271cq5pfw995qchh3a42j0l-abc-verifier-2022.03.04 q29bwjibv9gi9n86203s38n0577w09sx-glibc-2.33-117 sxjqmj5vh2212isg67b33qzr3c1pdw2h-libffi-3.4.2-dev yx1xvmzia0fd0pvlp7cxjdlvrsdkhkjj-readline-6.3p08
Deriver: x9kirzdbj1f4r50l71jvcc86il8r94xc-yosys-0.15.drv
Sig: cache.nixos.org-1:eJOBiYS+WArV7TmZbAwScAHSzRgYOmbaxk9MWexAYAx3x7g5UyP+xoLxdiAgmfRPd1tFzUBrJehW96QfA4sYDA=="#;
        let expected = r#"{ "StorePath": "/nix/store/dw2xrnys127khw71bjygg7hmny62243n-yosys-0.15", "URL": "nar/06yc663a4bsf4j76rwx97iz9lwy3fwmf8m2ck3in5bsyzvcyk0ds.nar.xz", "Compression": "xz", "FileHash": { "type": "sha256", "hash": "06yc663a4bsf4j76rwx97iz9lwy3fwmf8m2ck3in5bsyzvcyk0ds" }, "FileSize": 3542408, "NarHash": { "type": "sha256", "hash": "1mpyzqm3s45jpp598aqnc6d8359zf83gb6j3zlm87vjwg5jdhhm3" }, "NarSize": 17680416, "References": [ "18fz9jnhmfkzkh6p1iwwwng4i7x4rag7-gcc-10.3.0-lib", "20ix3np9v02ph8fwb2v41r5mzlfg8f73-libffi-3.4.2", "9b9ryxskcwh573jwjz6m5l01whkcb39a-zlib-1.2.11", "ab2ih3qiqkqjsapimxxyvzhxdwqcgyrn-tcl-8.6.11", "dndi916j6yxzfzzj2sma2llhrlwahq06-bash-5.1-p16", "dw2xrnys127khw71bjygg7hmny62243n-yosys-0.15", "fsq9kj579dnfygb12zcagbn1sg8dnl6d-protobuf-3.19.3", "hb1lzaisgx2m9n29hqhh6yp6hasplq1v-python3-3.9.10", "klq81kinj271cq5pfw995qchh3a42j0l-abc-verifier-2022.03.04", "q29bwjibv9gi9n86203s38n0577w09sx-glibc-2.33-117", "sxjqmj5vh2212isg67b33qzr3c1pdw2h-libffi-3.4.2-dev", "yx1xvmzia0fd0pvlp7cxjdlvrsdkhkjj-readline-6.3p08" ], "Deriver": "x9kirzdbj1f4r50l71jvcc86il8r94xc-yosys-0.15.drv", "Sig": { "cache.nixos.org-1": "eJOBiYS+WArV7TmZbAwScAHSzRgYOmbaxk9MWexAYAx3x7g5UyP+xoLxdiAgmfRPd1tFzUBrJehW96QfA4sYDA==" } }"#;

        let mut output = String::new();
        crate::narinfo::narinfo_to_json(input.to_string(), &mut output);
        assert_eq!(expected.trim(), output.trim());
    }

    #[test]
    fn test_fingerprint_path() {
        let path = "/nix/store/009ixrgv5dylkrpx5ylba8yxqcbis5bs-libfreeaptx-0.1.1";
        let hash = "sha256:0si0g30ksvlz953ysczn7jb0z942xzhrzwzx6h94f76r9k8269ph";
        let size = 64184;
        let refs = vec![
            "/nix/store/009ixrgv5dylkrpx5ylba8yxqcbis5bs-libfreeaptx-0.1.1",
            "/nix/store/d2bpliayddadf6lx6l1i04w265gqw8n6-glibc-2.34-210",
        ];

        let expected = "1;/nix/store/009ixrgv5dylkrpx5ylba8yxqcbis5bs-libfreeaptx-0.1.1;sha256:0si0g30ksvlz953ysczn7jb0z942xzhrzwzx6h94f76r9k8269ph;64184;/nix/store/009ixrgv5dylkrpx5ylba8yxqcbis5bs-libfreeaptx-0.1.1,/nix/store/d2bpliayddadf6lx6l1i04w265gqw8n6-glibc-2.34-210";

        let s = Store::new("/nix/store").unwrap();
        assert_eq!(
            s.fingerprint_path(&path, &hash, &size, refs).unwrap(),
            expected.to_string()
        );
    }

    #[test]
    fn test_secretkey_to_publickey() {
        let sk = "t:02b8uY8PDLI9lWvEEOnBulRlcGB7ATMNan/Rn61XdwpwD2pfgERF9TpUUuNBb5c6GwBRLV/niW78YUjrt2i71Q==";
        let pk = "t:cA9qX4BERfU6VFLjQW+XOhsAUS1f54lu/GFI67dou9U=";

        assert_eq!(sk_to_pk(sk).unwrap(), pk.to_string());
    }

    #[test]
    fn test_secretkey_to_keypair() {
        let sk = "t:02b8uY8PDLI9lWvEEOnBulRlcGB7ATMNan/Rn61XdwpwD2pfgERF9TpUUuNBb5c6GwBRLV/niW78YUjrt2i71Q==";
        assert!(
            sk_to_keypair(sk).is_ok(),
            "keypair should have been created"
        );
    }

    #[test]
    fn test_sign_narinfo() {
        let input = r#"StorePath: /nix/store/dw2xrnys127khw71bjygg7hmny62243n-yosys-0.15
URL: nar/06yc663a4bsf4j76rwx97iz9lwy3fwmf8m2ck3in5bsyzvcyk0ds.nar.xz
Compression: xz
FileHash: sha256:06yc663a4bsf4j76rwx97iz9lwy3fwmf8m2ck3in5bsyzvcyk0ds
FileSize: 3542408
NarHash: sha256:1mpyzqm3s45jpp598aqnc6d8359zf83gb6j3zlm87vjwg5jdhhm3
NarSize: 17680416
References: 18fz9jnhmfkzkh6p1iwwwng4i7x4rag7-gcc-10.3.0-lib 20ix3np9v02ph8fwb2v41r5mzlfg8f73-libffi-3.4.2 9b9ryxskcwh573jwjz6m5l01whkcb39a-zlib-1.2.11 ab2ih3qiqkqjsapimxxyvzhxdwqcgyrn-tcl-8.6.11 dndi916j6yxzfzzj2sma2llhrlwahq06-bash-5.1-p16 dw2xrnys127khw71bjygg7hmny62243n-yosys-0.15 fsq9kj579dnfygb12zcagbn1sg8dnl6d-protobuf-3.19.3 hb1lzaisgx2m9n29hqhh6yp6hasplq1v-python3-3.9.10 klq81kinj271cq5pfw995qchh3a42j0l-abc-verifier-2022.03.04 q29bwjibv9gi9n86203s38n0577w09sx-glibc-2.33-117 sxjqmj5vh2212isg67b33qzr3c1pdw2h-libffi-3.4.2-dev yx1xvmzia0fd0pvlp7cxjdlvrsdkhkjj-readline-6.3p08
Deriver: x9kirzdbj1f4r50l71jvcc86il8r94xc-yosys-0.15.drv
Sig: cache.nixos.org-1:eJOBiYS+WArV7TmZbAwScAHSzRgYOmbaxk9MWexAYAx3x7g5UyP+xoLxdiAgmfRPd1tFzUBrJehW96QfA4sYDA=="#;

        let s = Store::new("/nix/store").unwrap();
        let sk = "t:02b8uY8PDLI9lWvEEOnBulRlcGB7ATMNan/Rn61XdwpwD2pfgERF9TpUUuNBb5c6GwBRLV/niW78YUjrt2i71Q==";
        let keys = sk_to_keypair(sk).unwrap();

        let sig = sign_narinfo(&s, &keys, input).unwrap();
        assert_eq!("t:DWUrR00frjSmaW5lRGmLxQ4TptkggNxiqDtkfZsJcSfleCIT4Qaw+orizNxxnPmhpLOeVhws5BjPzBznzgzkCA==", sig);
    }
}
