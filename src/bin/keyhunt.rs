//! Hunts for the (new, 7.1) RSA private key inside the installed game
//! binaries and tests every candidate against the captured undecryptable
//! seed blob from the token response dump.
//!
//! PKCS#1 RSAPrivateKey DER for a 2048-bit key contains the byte signature
//! `02 01 00 02 82 01 01` (INTEGER version=0, INTEGER 257-byte modulus).
//! We scan for that signature, parse the surrounding key, and try to
//! decrypt the captured blob — a match is provable (yields an 8-byte seed).

use std::path::PathBuf;

use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey};

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

/// Locate the game install directory from the game's own output log
/// (same trick stardb-exporter uses).
fn find_game_dir() -> Option<PathBuf> {
    let appdata = std::env::var("APPDATA").ok()?;
    let mut low = PathBuf::from(appdata);
    low.pop();
    low.push("LocalLow");
    low.push("miHoYo");

    for sub in ["Genshin Impact", "原神"] {
        let log = low.join(sub).join("output_log.txt");
        let Ok(text) = std::fs::read_to_string(&log) else { continue };
        for line in text.lines() {
            for marker in ["GenshinImpact_Data", "YuanShen_Data"] {
                if let Some(pos) = line.find(marker) {
                    // Walk back to the drive letter ("X:\").
                    let head = &line[..pos];
                    if let Some(colon) = head.rfind(':') {
                        if colon >= 1 {
                            let start = colon - 1;
                            return Some(PathBuf::from(&line[start..pos]));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract the two RSA-encrypted blobs from the token response dump.
fn extract_blobs(rsp: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use base64::prelude::*;
    let mut blobs_256 = Vec::new();
    let mut i = 0usize;
    let mut order = 0usize;
    while i < rsp.len() {
        let Some(key) = read_varint(rsp, &mut i) else { break };
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        if field == 0 {
            break;
        }
        match wire {
            0 => {
                if read_varint(rsp, &mut i).is_none() {
                    break;
                }
            }
            1 => i += 8,
            5 => i += 4,
            2 => {
                let Some(len) = read_varint(rsp, &mut i) else { break };
                let len = len as usize;
                if i + len > rsp.len() {
                    break;
                }
                let raw = &rsp[i..i + len];
                i += len;
                if let Ok(decoded) = BASE64_STANDARD.decode(raw) {
                    if decoded.len() == 256 {
                        blobs_256.push(decoded);
                    }
                }
            }
            _ => break,
        }
    }
    // blobs in wire order: [first(unknown), second(legacy/known)]
    if blobs_256.len() == 2 {
        (blobs_256[0].clone(), blobs_256[1].clone())
    } else {
        (Vec::new(), Vec::new())
    }
}

/// Parse a DER INTEGER starting at `*i` (tag 0x02) into a BigUint.
fn read_der_int(data: &[u8], i: &mut usize) -> Option<BigUint> {
    if *i >= data.len() || data[*i] != 0x02 {
        return None;
    }
    *i += 1;
    let len = match data.get(*i) {
        Some(&l) if l & 0x80 == 0 => {
            *i += 1;
            l as usize
        }
        Some(&0x81) => {
            *i += 1;
            let l = *data.get(*i)? as usize;
            *i += 1;
            l
        }
        Some(&0x82) => {
            *i += 1;
            let l = u16::from_be_bytes([*data.get(*i)?, *data.get(*i + 1)?]) as usize;
            *i += 2;
            l
        }
        _ => return None,
    };
    let bytes = data.get(*i..*i + len)?;
    *i += len;
    Some(BigUint::from_bytes_be(bytes))
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
    let (unknown_blob, legacy_blob) = extract_blobs(&rsp);
    assert!(!unknown_blob.is_empty(), "no blobs found in dump");
    std::fs::write(dump_dir.join("blob_unknown.bin"), &unknown_blob).unwrap();
    std::fs::write(dump_dir.join("blob_legacy.bin"), &legacy_blob).unwrap();
    println!("blobs extracted (unknown/legacy): {}/{} bytes", unknown_blob.len(), legacy_blob.len());

    // Sanity: legacy blob must decrypt with key 5.
    let key5 = RsaPrivateKey::from_pkcs1_pem(&std::fs::read_to_string(
        "vendor/auto-artifactarium/keys/private_key_5.pem",
    ).unwrap()).unwrap();
    assert!(
        key5.decrypt(Pkcs1v15Encrypt, &legacy_blob).is_ok(),
        "legacy blob does not decrypt with key 5 — dump mismatch"
    );
    println!("sanity: legacy blob decrypts with key 5 ✔");

    let game_dir = find_game_dir().expect("game directory not found");
    println!("game dir: {}", game_dir.display());

    let mut targets = vec![game_dir.join("GenshinImpact.exe"), game_dir.join("UnityPlayer.dll")];
    let ua = game_dir.join("Plugins").join("x86_64").join("UserAssembly.dll");
    targets.push(ua);

    // PKCS#1 RSAPrivateKey for 2048-bit: SEQUENCE { INTEGER 0, INTEGER n(257), ... }
    let signature: [u8; 7] = [0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01];

    let mut candidates = 0usize;
    let mut found = false;

    for target in &targets {
        let Ok(data) = std::fs::read(target) else {
            println!("skip (not found): {}", target.display());
            continue;
        };
        println!("scanning {} ({} MB)", target.display(), data.len() / 1024 / 1024);

        let mut i = 0usize;
        while i + signature.len() <= data.len() {
            if &data[i..i + signature.len()] != &signature {
                i += 1;
                continue;
            }
            let mut p = i;
            let _version = read_der_int(&data, &mut p);
            let Some(n) = read_der_int(&data, &mut p) else { i += 1; continue };
            let Some(e) = read_der_int(&data, &mut p) else { i += 1; continue };
            let Some(d) = read_der_int(&data, &mut p) else { i += 1; continue };
            let Some(prime_p) = read_der_int(&data, &mut p) else { i += 1; continue };
            let Some(prime_q) = read_der_int(&data, &mut p) else { i += 1; continue };

            candidates += 1;
            match RsaPrivateKey::from_components(n.clone(), e.clone(), d.clone(), vec![prime_p, prime_q]) {
                Ok(key) => {
                    if let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, &unknown_blob) {
                        let hex = plain.iter().map(|b| format!("{b:02x}")).collect::<String>();
                        println!(
                            "!!! KEY FOUND at offset {i:#x} in {}: {} bits, decrypts unknown blob -> {} bytes: {hex}",
                            target.display(),
                            key.n().bits(),
                            plain.len(),
                        );
                        let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
                        let out = dump_dir.join("private_key_6.pem");
                        std::fs::write(&out, pem.to_string()).unwrap();
                        println!("saved {}", out.display());
                        found = true;
                    }
                }
                Err(_) => {}
            }
            i += 1;
        }
    }

    println!("scanned {candidates} candidate keys");
    if !found {
        println!("no candidate decrypts the unknown blob (key may be obfuscated/derived at runtime)");
    }
}
