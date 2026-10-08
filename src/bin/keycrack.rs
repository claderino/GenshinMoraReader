//! Offline key-derivation analysis for captured keydump artifacts.
//!
//! Loads the encrypted command + metadata dumped by the reader when the
//! session key could not be derived, and tests candidate derivations
//! against the known plaintext magic (0x45 0x67 … 0x89 0xAB).

use std::path::PathBuf;

use rand_mt::Mt64;

// ---------------------------------------------------------------------------
// Replications of the library's primitives
// ---------------------------------------------------------------------------

/// Upstream `new_key_from_seed`: double MT64 init, one skipped draw, 512
/// big-endian u64s (4096 bytes).
fn key_upstream(seed: u64) -> Vec<u8> {
    let mut first = Mt64::new(seed);
    let mut generator = Mt64::new(first.next_u64());
    let _ = generator.next_u64(); // skip
    let mut key = Vec::with_capacity(4096);
    for _ in 0..512 {
        key.extend_from_slice(&generator.next_u64().to_be_bytes());
    }
    key
}

/// Variant: single MT64 init, no re-seeding, no skip.
fn key_single_mt(seed: u64) -> Vec<u8> {
    let mut generator = Mt64::new(seed);
    let mut key = Vec::with_capacity(4096);
    for _ in 0..512 {
        key.extend_from_slice(&generator.next_u64().to_be_bytes());
    }
    key
}

/// Variant: double init, little-endian output.
fn key_upstream_le(seed: u64) -> Vec<u8> {
    let mut first = Mt64::new(seed);
    let mut generator = Mt64::new(first.next_u64());
    let _ = generator.next_u64();
    let mut key = Vec::with_capacity(4096);
    for _ in 0..512 {
        key.extend_from_slice(&generator.next_u64().to_le_bytes());
    }
    key
}

/// Variant: single init, little-endian.
fn key_single_mt_le(seed: u64) -> Vec<u8> {
    let mut generator = Mt64::new(seed);
    let mut key = Vec::with_capacity(4096);
    for _ in 0..512 {
        key.extend_from_slice(&generator.next_u64().to_le_bytes());
    }
    key
}

/// C# System.Random emulation (copied from the vendored crate).
struct CsRandom {
    m_big: i32,
    m_seed: i32,
    inext: i32,
    inextp: i32,
    seed_array: [i32; 56],
}

impl CsRandom {
    fn seeded(seed: i32) -> Self {
        let mut rand = CsRandom {
            m_big: i32::MAX,
            m_seed: 161803398,
            inext: 0,
            inextp: 0,
            seed_array: [0; 56],
        };
        let subtraction = if seed == i32::MIN { i32::MAX } else { i32::abs(seed) };
        let mut mj = rand.m_seed - subtraction;
        rand.seed_array[55] = mj;
        let mut mk = 1i32;
        for i in 1..55 {
            let ii = 21 * i % 55;
            rand.seed_array[ii] = mk;
            mk = mj - mk;
            if mk < 0 {
                mk += rand.m_big;
            }
            mj = rand.seed_array[ii];
        }
        for _ in 1..5 {
            for i in 1..56 {
                rand.seed_array[i] = rand.seed_array[i].wrapping_sub(rand.seed_array[1 + (i + 30) % 55]);
                if rand.seed_array[i] < 0 {
                    rand.seed_array[i] += rand.m_big;
                }
            }
        }
        rand.inext = 0;
        rand.inextp = 21;
        rand
    }

    fn internal_sample(&mut self) -> i32 {
        let mut loc_inext = self.inext;
        let mut loc_inextp = self.inextp;
        loc_inext += 1;
        if loc_inext >= 56 {
            loc_inext = 1;
        }
        loc_inextp += 1;
        if loc_inextp >= 56 {
            loc_inextp = 1;
        }
        let mut ret = self.seed_array[loc_inext as usize] - self.seed_array[loc_inextp as usize];
        if ret == self.m_big {
            ret -= 1;
        }
        if ret < 0 {
            ret += self.m_big;
        }
        self.seed_array[loc_inext as usize] = ret;
        self.inext = loc_inext;
        self.inextp = loc_inextp;
        ret
    }

    fn next_double(&mut self) -> f64 {
        (self.internal_sample() as f64) * (1.0 / (self.m_big as f64))
    }

    fn next_safe_uint64(&mut self) -> u64 {
        (self.next_double() * (u64::MAX as f64)) as u64
    }
}

// ---------------------------------------------------------------------------
// Magic check
// ---------------------------------------------------------------------------

fn check(key: &[u8], ct: &[u8]) -> bool {
    if ct.len() < 4 || key.len() < 4 {
        return false;
    }
    let n = ct.len();
    let kl = key.len();
    (ct[0] ^ key[0]) == 0x45
        && (ct[1] ^ key[1]) == 0x67
        && (ct[n - 2] ^ key[(n - 2) % kl]) == 0x89
        && (ct[n - 1] ^ key[(n - 1) % kl]) == 0xAB
}

// Partial check (first magic only) — for quickly filtering candidates before
// a full generation is worth reporting.
fn check_head(key8: [u8; 8], ct: &[u8]) -> bool {
    (ct[0] ^ key8[0]) == 0x45 && (ct[1] ^ key8[1]) == 0x67
}

fn keygen_of(variant: u8, seed: u64) -> Vec<u8> {
    match variant {
        0 => key_upstream(seed),
        1 => key_single_mt(seed),
        2 => key_upstream_le(seed),
        _ => key_single_mt_le(seed),
    }
}

const VARIANT_NAMES: [&str; 4] = [
    "upstream(double-mt,be)",
    "single-mt,be",
    "upstream(double-mt,le)",
    "single-mt,le",
];

fn main() {
    let dump_dir = PathBuf::from(
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA"),
    )
    .join("GenshinReader")
    .join("keydump");

    let mut ct_file = None;
    let mut meta_file = None;
    for entry in std::fs::read_dir(&dump_dir).expect("keydump dir") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("keyfail_") && name.ends_with(".bin") && ct_file.is_none() {
            ct_file = Some(entry.path());
        } else if name.starts_with("keyfail_") && name.ends_with(".meta") && meta_file.is_none() {
            meta_file = Some(entry.path());
        }
    }
    let ct = std::fs::read(ct_file.expect("keyfail bin")).expect("read ciphertext");
    let meta = std::fs::read_to_string(meta_file.expect("keyfail meta")).expect("read meta");

    let mut center = 0u64;
    let mut server_seed = 0u64;
    let mut wall = 0u64;
    for line in meta.lines() {
        if let Some(v) = line.strip_prefix("sent_time_center=") {
            center = v.parse().unwrap();
        } else if let Some(v) = line.strip_prefix("server_seed=") {
            server_seed = v.parse().unwrap();
        } else if let Some(v) = line.strip_prefix("wall_epoch_ms=") {
            wall = v.parse().unwrap();
        }
    }

    println!("ciphertext: {} bytes", ct.len());
    println!("center (sent_ms) = {center}");
    println!("server_seed      = {server_seed}");
    println!("wall epoch ms    = {wall}");
    println!();

    let mut attempts: u64 = 0;
    let mut found: Option<String> = None;

    let mut report = |desc: String| {
        println!("*** MATCH: {desc} ***");
    };

    // Hypothesis 1: seed is the server seed alone (no client component).
    for variant in 0..4u8 {
        attempts += 1;
        if check(&keygen_of(variant, server_seed), &ct) {
            found = Some(format!("direct server_seed, {}", VARIANT_NAMES[variant as usize]));
            report(found.clone().unwrap());
        }
    }

    // Hypothesis 2: seed = server_seed ^ sent_time / wall clock variants.
    for other in [center, wall] {
        for variant in 0..4u8 {
            attempts += 1;
            if check(&keygen_of(variant, server_seed ^ other), &ct) {
                found = Some(format!(
                    "server_seed ^ time({other}), {}",
                    VARIANT_NAMES[variant as usize]
                ));
                report(found.clone().unwrap());
            }
        }
    }

    // Hypothesis 3: full upstream formula — C# Random seeded by client ms
    // (swept around both the reported time and the true wall clock), taking
    // one of the first draws, combined by XOR (and try ADD too).
    for time_center in [center as i64, wall as i64] {
        for delta in -3000i64..=3000 {
            let client_ms = time_center + delta;
            let mut cs = CsRandom::seeded(client_ms as i32);
            // First few draws of the generator as candidate client seeds.
            let mut draws = Vec::with_capacity(4);
            for _ in 0..4 {
                draws.push(cs.next_safe_uint64());
            }
            for (draw_idx, &client_seed) in draws.iter().enumerate() {
                for combine in 0..2 {
                    let seed = if combine == 0 {
                        client_seed ^ server_seed
                    } else {
                        client_seed.wrapping_add(server_seed)
                    };
                    for variant in 0..4u8 {
                        attempts += 1;
                        let key = keygen_of(variant, seed);
                        if check(&key, &ct) {
                            found = Some(format!(
                                "cs_random(client_ms={client_ms}, draw#{draw_idx}, {}) [delta={delta}], {}",
                                if combine == 0 { "xor" } else { "add" },
                                VARIANT_NAMES[variant as usize]
                            ));
                            report(found.clone().unwrap());
                        }
                    }
                }
            }
        }
    }

    println!("tested {attempts} derivations");
    if found.is_none() {
        println!("no match — derivation space needs widening");
        // Print the key-byte constraints for further analysis.
        let kl = 4096;
        let n = ct.len();
        println!(
            "key[0]={:#04x} key[1]={:#04x} key[{}]={:#04x} key[{}]={:#04x} (for 4096-byte key)",
            ct[0] ^ 0x45,
            ct[1] ^ 0x67,
            (n - 2) % kl,
            ct[n - 2] ^ 0x89,
            (n - 1) % kl,
            ct[n - 1] ^ 0xAB,
        );
    }
}
