//! keyhunt v2 — deep static search for RSA key material in the installed
//! game files, validated against the captured "unknown blob" oracle.
//!
//! Strategies:
//! 1. Calibration: locate the KNOWN key 5 (raw DER slice, raw modulus, and
//!    base64-string forms) — tells us where keys live and in what encoding.
//! 2. Structural scans: PKCS#1 DER signature, PKCS#8 header, PEM text.
//! 3. Every PKCS#1-shaped candidate is constructed and tested against the
//!    captured undecryptable blob (and the legacy blob as a sanity oracle).
//! 4. Targeted string search in IL2CPP metadata for login/key-related names.

use base64::Engine;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey};

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

fn try_parse_pkcs1_at(data: &[u8], start: usize) -> Option<RsaPrivateKey> {
    let mut p = start;
    let _version = read_der_int(data, &mut p)?;
    let n = read_der_int(data, &mut p)?;
    let e = read_der_int(data, &mut p)?;
    let d = read_der_int(data, &mut p)?;
    let prime_p = read_der_int(data, &mut p)?;
    let prime_q = read_der_int(data, &mut p)?;
    RsaPrivateKey::from_components(n, e, d, vec![prime_p, prime_q]).ok()
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            hits.push(i);
            if hits.len() > 64 {
                break;
            }
        }
        i += 1;
    }
    hits
}

fn main() {
    let dump_dir = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("GenshinReader")
        .join("keydump");
    let blob_unknown = std::fs::read(dump_dir.join("blob_unknown.bin")).expect("oracle blob");
    let blob_legacy = std::fs::read(dump_dir.join("blob_legacy.bin")).expect("legacy blob");

    let key5 = RsaPrivateKey::from_pkcs1_pem(&std::fs::read_to_string(
        "vendor/auto-artifactarium/keys/private_key_5.pem",
    )
    .unwrap())
    .unwrap();
    assert!(key5.decrypt(Pkcs1v15Encrypt, &blob_legacy).is_ok());

    // Calibration material derived from the known key.
    let key5_der = key5
        .to_pkcs1_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let fingerprint = &key5_der[64..192]; // mid-key slice, unique
    let key5_b64 = base64::engine::general_purpose::STANDARD
        .encode(&key5_der)
        .into_bytes();
    let b64_probe = &key5_b64[0..48]; // ASCII prefix if stored as a b64 string

    let game_dir = std::path::PathBuf::from("E:/Star rail/GenshinImpact/Genshin Impact game");
    let targets: Vec<std::path::PathBuf> = vec![
        game_dir.join("GenshinImpact.exe"),
        game_dir.join("mhypbase.dll"),
        game_dir.join("rtlbase.dll"),
        game_dir.join("GenshinImpact_Data/Plugins/kcp.dll"),
        game_dir.join("GenshinImpact_Data/Native/Data/Metadata/global-metadata.dat"),
        game_dir.join("GenshinImpact_Data/Native/Data/Metadata/startup-metadata.dat"),
        game_dir.join("GenshinImpact_Data/Native/Data/etc/mono/4.0/machine.config"),
    ];

    const PKCS1_SIG: [u8; 7] = [0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01];
    const PKCS8_SIG: [u8; 11] = [
        0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    ];
    const PEM_BEGIN: &[u8] = b"-----BEGIN";

    let mut candidates_tested = 0usize;
    let mut found_key6 = false;

    for target in &targets {
        let Ok(data) = std::fs::read(target) else {
            println!("skip: {}", target.display());
            continue;
        };
        let name = target.file_name().unwrap().to_string_lossy();
        println!(
            "scanning {} ({} MB)",
            name,
            data.len() / 1024 / 1024
        );

        // Calibration probes.
        let raw_hits = find_all(&data, fingerprint);
        let b64_hits = find_all(&data, b64_probe);
        if !raw_hits.is_empty() {
            println!("  !!! key5 DER found RAW at {:?}", raw_hits.iter().take(4).collect::<Vec<_>>());
        }
        if !b64_hits.is_empty() {
            println!("  !!! key5 base64 TEXT found at {:?}", b64_hits.iter().take(4).collect::<Vec<_>>());
        }
        if raw_hits.is_empty() && b64_hits.is_empty() {
            println!("  calibration: key5 not present (raw or b64)");
        }

        // PKCS#1 structural candidates.
        for hit in find_all(&data, &PKCS1_SIG) {
            if let Some(key) = try_parse_pkcs1_at(&data, hit) {
                candidates_tested += 1;
                let opens_legacy = key.decrypt(Pkcs1v15Encrypt, &blob_legacy).is_ok();
                if let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, &blob_unknown) {
                    let hex: String = plain.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    println!(
                        "  !!! KEY6 CANDIDATE at {hit:#x}: opens unknown blob -> {} bytes: {hex}",
                        plain.len()
                    );
                    let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
                    let out = dump_dir.join("private_key_6.pem");
                    std::fs::write(&out, pem.to_string()).unwrap();
                    println!("  saved {}", out.display());
                    found_key6 = true;
                } else if !opens_legacy {
                    println!("  candidate at {hit:#x}: opens neither blob");
                } else {
                    println!("  candidate at {hit:#x}: = key5 (legacy oracle)");
                }
            }
        }

        // PKCS#8-wrapped candidates: parse the inner PKCS#1 after the header.
        for hit in find_all(&data, &PKCS8_SIG) {
            // inner DER starts after AlgorithmIdentifier + OCTET STRING tag
            let mut probe = hit + PKCS8_SIG.len();
            // skip: 06 09 <oid9> 05 00 04 82 <len2>
            if data.get(probe) == Some(&0x06) {
                let oid_len = *data.get(probe + 1).unwrap_or(&0) as usize;
                probe += 2 + oid_len;
                if data.get(probe) == Some(&0x05) {
                    probe += 2; // NULL
                    if data.get(probe) == Some(&0x04) {
                        probe += 1;
                        let l = match data.get(probe) {
                            Some(&0x82) => {
                                let v = u16::from_be_bytes([
                                    *data.get(probe + 1).unwrap_or(&0),
                                    *data.get(probe + 2).unwrap_or(&0),
                                ]) as usize;
                                probe += 3;
                                v
                            }
                            _ => continue,
                        };
                        let _ = l;
                        if let Some(key) = try_parse_pkcs1_at(&data, probe) {
                            candidates_tested += 1;
                            if let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, &blob_unknown) {
                                let hex: String =
                                    plain.iter().map(|b| format!("{b:02x}")).collect::<String>();
                                println!("  !!! KEY6 (PKCS#8) at {hit:#x}: {} bytes {hex}", plain.len());
                                let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
                                std::fs::write(dump_dir.join("private_key_6.pem"), pem.to_string())
                                    .unwrap();
                                found_key6 = true;
                            }
                        }
                    }
                }
            }
        }

        // PEM text blocks.
        for hit in find_all(&data, PEM_BEGIN) {
            let scan_end = (hit + 4096).min(data.len());
            let end = data[hit..scan_end]
                .windows(8)
                .position(|w| w == b"-----END")
                .map(|p| hit + p + 64)
                .unwrap_or(scan_end);
            let text = String::from_utf8_lossy(&data[hit..end]).to_string();
            if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(&text) {
                candidates_tested += 1;
                if let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, &blob_unknown) {
                    println!("  !!! KEY6 (PEM) at {hit:#x}: {} bytes", plain.len());
                    std::fs::write(
                        dump_dir.join("private_key_6.pem"),
                        key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap().to_string(),
                    )
                    .unwrap();
                    found_key6 = true;
                }
            }
        }

        // Targeted metadata strings.
        if name.contains("metadata") {
            for probe_str in ["GetPlayerToken", "PlayerTokenRsp", "GenKey", "RsaKey"] {
                let hits = find_all(&data, probe_str.as_bytes());
                if !hits.is_empty() {
                    println!(
                        "  string '{probe_str}' at {:?}",
                        hits.iter().take(3).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    println!("structural candidates tested: {candidates_tested}");
    if !found_key6 {
        println!("no key for the unknown blob found in static scan");
    }
}
