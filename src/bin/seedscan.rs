//! Scans every captured (dispatch-decrypted) token response dump: extracts
//! all base64 256-byte blobs and reports which open with the known RSA keys.

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

    let mut rsp_files = Vec::new();
    for entry in std::fs::read_dir(&dump_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("token_rsp_decrypted_") && name.ends_with(".bin") {
            rsp_files.push(entry.path());
        }
    }
    rsp_files.sort();
    println!("{} token response dumps", rsp_files.len());

    let keys_dir = PathBuf::from("vendor/auto-artifactarium/keys");
    let mut keys: Vec<(String, RsaPrivateKey)> = Vec::new();
    for name in ["private_key_4.pem", "private_key_5.pem"] {
        let key =
            RsaPrivateKey::from_pkcs1_pem(&std::fs::read_to_string(keys_dir.join(name)).unwrap())
                .unwrap();
        keys.push((name.trim_start_matches("private_key_").trim_end_matches(".pem").to_string(), key));
    }

    for rsp_file in &rsp_files {
        let rsp = std::fs::read(rsp_file).unwrap();
        let stamp = rsp_file
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches("token_rsp_decrypted_")
            .to_string();

        // Collect every base64 field decoding to 256 bytes, in wire order.
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        let mut i = 0usize;
        while i < rsp.len() {
            let Some(key) = read_varint(&rsp, &mut i) else { break };
            let field = (key >> 3) as u32;
            let wire = (key & 7) as u8;
            if field == 0 {
                break;
            }
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
                    if let Ok(decoded) = BASE64_STANDARD.decode(raw) {
                        if decoded.len() == 256 {
                            blobs.push(decoded);
                        }
                    }
                }
                _ => break,
            }
        }

        let mut line = format!("{stamp} len={:<5} blobs={}:", rsp.len(), blobs.len());
        for (idx, blob) in blobs.iter().enumerate() {
            let mut opened = String::new();
            for (key_name, key) in &keys {
                if let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, blob) {
                    let hex: String = plain.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    opened.push_str(&format!(
                        " [blob{idx} k{key_name}: {}B {}]",
                        plain.len(),
                        &hex[..hex.len().min(8)]
                    ));
                }
            }
            if opened.is_empty() {
                line.push_str(&format!(" [blob{idx}: none]"));
            } else {
                line.push_str(&opened);
            }
        }
        println!("{line}");
    }
    println!("done");
}
