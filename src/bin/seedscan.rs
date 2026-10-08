//! Scans a dumped (dispatch-decrypted) GetPlayerTokenRsp for every
//! length-delimited field, attempts base64 decode + RSA decryption with the
//! library keys, and reports which field yields an 8-byte seed — and which
//! candidate blobs remain undecryptable (e.g. new-format RSA-2048 blocks).

use std::collections::HashMap;
use std::path::PathBuf;

use base64::prelude::*;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    while *i < buf.len() {
        let b = buf[*i];
        *i += 1;
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn main() {
    let dump_dir = PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("GenshinReader")
        .join("keydump");

    let mut rsp_file = None;
    for entry in std::fs::read_dir(&dump_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("token_rsp_decrypted_") && name.ends_with(".bin") {
            rsp_file = Some(entry.path());
        }
    }
    let rsp = std::fs::read(rsp_file.expect("token rsp dump")).unwrap();

    let keys_dir = PathBuf::from("vendor/auto-artifactarium/keys");
    let mut keys: Vec<(String, RsaPrivateKey)> = Vec::new();
    for name in ["private_key_4.pem", "private_key_5.pem"] {
        let key = RsaPrivateKey::from_pkcs1_pem(
            &std::fs::read_to_string(keys_dir.join(name)).unwrap(),
        )
        .unwrap();
        let bits = key.n().bits();
        println!("loaded {name}: {bits}-bit, {}-byte modulus", (bits + 7) / 8);
        keys.push((name.to_string(), key));
    }

    // Walk all length-delimited fields (top level).
    let mut i = 0usize;
    let mut index = 0usize;
    while i < rsp.len() {
        let Some(key) = read_varint(&rsp, &mut i) else { break };
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        if field == 0 {
            break;
        }
        index += 1;
        match wire {
            0 => {
                if read_varint(&rsp, &mut i).is_none() {
                    break;
                }
            }
            1 => i += 8,
            5 => i += 4,
            2 => {
                let Some(len) = read_varint(&rsp, &mut i) else { break };
                let len = len as usize;
                if i + len > rsp.len() {
                    break;
                }
                let raw = &rsp[i..i + len];
                i += len;

                // Candidate encrypted material: raw length matching a key
                // modulus, or base64 text decoding to such a length.
                let mut candidates: Vec<(String, Vec<u8>)> = Vec::new();
                candidates.push((format!("raw[{len}]"), raw.to_vec()));
                if let Ok(decoded) = BASE64_STANDARD.decode(raw) {
                    candidates.push((format!("b64[{len}]={}", decoded.len()), decoded));
                }

                for (desc, data) in candidates {
                    for (key_name, key) in &keys {
                        let modulus = (key.n().bits() + 7) / 8;
                        if data.len() != modulus {
                            continue;
                        }
                        let mut results: Vec<(&str, Result<Vec<u8>, _>)> = Vec::new();
                        results.push(("pkcs1v15", key.decrypt(Pkcs1v15Encrypt, &data)));
                        for (label, padding) in [
                            ("oaep-sha1", rsa::Oaep::new::<sha1::Sha1>()),
                            ("oaep-sha256", rsa::Oaep::new::<sha2::Sha256>()),
                        ] {
                            results.push((label, key.decrypt(rsa::Oaep::from(padding), &data)));
                        }
                        let mut any = false;
                        for (label, result) in results {
                            if let Ok(plain) = result {
                                any = true;
                                let hex =
                                    plain.iter().map(|b| format!("{b:02x}")).collect::<String>();
                                println!(
                                    "field {field} #{index} {desc}: DECRYPTS with {key_name}/{label} -> {} bytes {hex}{}",
                                    plain.len(),
                                    if plain.len() == 8 { " *** 8-BYTE SEED ***" } else { "" },
                                );
                            }
                        }
                        if !any {
                            println!(
                                "field {field} #{index} {desc}: {modulus}-byte block, {key_name} fails (all paddings)",
                            );
                        }
                    }
                }
            }
            _ => break,
        }
    }
    println!("done");
}
