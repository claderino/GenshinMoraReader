//! GenshinReader — passively records every Mora gain from Genshin Impact
//! network traffic, including what action produced it.
//!
//! Pipeline: pktmon (ETW) capture of UDP 22101/22102 → auto-artifactarium
//! (KCP reassembly + session-key capture + XOR decrypt) → value-pattern
//! protobuf detection of Mora events → JSONL ledger + live console feed.

// Release builds: GUI subsystem (no console window) for the default GUI
// mode; tracing goes to %LOCALAPPDATA%\GenshinReader\app.log. Debug
// builds keep the console. CLI subcommands with console output run via
// `debug_assertions` builds or redirect explicitly.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod admin;
mod capture;
mod detect;
mod gui;
mod ledger;
mod proto_walk;
mod reasons;

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use auto_artifactarium::{ConnectionPacket, GamePacket, GameSniffer};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use detect::MoraEvent;
use protobuf::Message;

const KEYS_JSON: &[u8] = include_bytes!("../keys/gi.json");

#[derive(Parser)]
#[command(
    name = "genshin-mora-reader",
    version,
    about = "Records every Mora gain from Genshin Impact network traffic",
    after_help = "USAGE FLOW:\n  1. Start this tool (GUI opens after the UAC prompt)\n  2. Launch Genshin Impact FRESH and log in (cold start — relogins use an\n     encrypted key exchange that can't currently be decrypted)\n  3. Every Mora change appears live in the window and is saved to the ledger\n  4. Use the GUI buttons (or the `summary` subcommand) for totals / CSV / clipboard"
)]
struct Cli {
    /// Path to the JSONL ledger file
    #[arg(long, global = true)]
    jsonl: Option<PathBuf>,

    /// Skip the automatic UAC elevation prompt (capture will fail unless
    /// already elevated)
    #[arg(long, global = true)]
    no_elevate: bool,

    /// Print capture diagnostics every 15s (packet counts per network
    /// component — useful when testing through a VPN)
    #[arg(long, global = true)]
    stats: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the graphical tracker (default when launched without arguments)
    Gui,

    /// Listen for game traffic and record Mora events (console mode)
    Capture,

    /// Show recorded Mora events with totals; optionally export
    Summary {
        /// Show a specific date (YYYY-MM-DD); defaults to today
        #[arg(long)]
        date: Option<String>,

        /// Include all recorded dates
        #[arg(long)]
        all: bool,

        /// Only show events for one account UID (uses mora_<uid>.jsonl)
        #[arg(long)]
        uid: Option<u32>,

        /// Write rows to a CSV file
        #[arg(long)]
        csv: Option<PathBuf>,

        /// Copy rows to the clipboard as TSV (paste into Google Sheets)
        #[arg(long)]
        clipboard: bool,
    },
}

fn default_ledger_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("GenshinReader").join("mora.jsonl")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ledger_path = cli.jsonl.clone().unwrap_or_else(default_ledger_path);

    match cli.command.unwrap_or(Command::Gui) {
        Command::Gui => run_gui(ledger_path, cli.no_elevate),
        Command::Capture => run_capture(ledger_path, cli.no_elevate, cli.stats).await,
        Command::Summary { date, all, uid, csv, clipboard } => {
            let ledger_path = match uid {
                // Per-account ledger file lives beside the default one.
                Some(uid) => ledger_path
                    .parent()
                    .map(|p| p.to_path_buf().join(format!("mora_{uid}.jsonl")))
                    .unwrap_or_else(|| PathBuf::from(format!("mora_{uid}.jsonl"))),
                None => ledger_path,
            };
            run_summary(ledger_path, date, all, csv, clipboard, uid)
        }
    }
}

pub(crate) fn load_keys() -> Result<HashMap<u16, Vec<u8>>> {
    let encoded: HashMap<u16, String> =
        serde_json::from_slice(KEYS_JSON).context("parsing embedded dispatch keys")?;
    let mut keys = HashMap::new();
    for (id, b64) in encoded {
        keys.insert(id, BASE64_STANDARD.decode(b64)?);
    }
    Ok(keys)
}

fn run_gui(ledger_path: PathBuf, no_elevate: bool) -> Result<()> {
    // Packet capture via ETW needs elevation; the game key exchange needs the
    // tool running before login, so elevate up front (single UAC prompt).
    if !admin::is_elevated() {
        if no_elevate {
            anyhow::bail!("packet capture requires admin rights — rerun elevated (or without --no-elevate)");
        }
        println!("Requesting administrator rights (needed for packet capture)...");
        admin::relaunch_elevated()?;
        return Ok(());
    }
    gui::run(ledger_path)
}

/// Release builds run with the windows GUI subsystem (no console), so
/// tracing goes to a log file instead of stdout.
#[cfg(not(debug_assertions))]
mod log_file {
    use std::fs::File;
    use std::io::Write;
    use std::sync::Mutex;
    use tracing_subscriber::fmt::MakeWriter;

    static FILE: Mutex<Option<File>> = Mutex::new(None);

    pub fn open(path: &std::path::Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            *FILE.lock().unwrap() = Some(f);
        }
    }

    pub struct W;
    impl Write for W {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut g) = FILE.lock() {
                if let Some(f) = g.as_mut() {
                    let _ = f.write(buf);
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if let Ok(mut g) = FILE.lock() {
                if let Some(f) = g.as_mut() {
                    let _ = f.flush();
                }
            }
            Ok(())
        }
    }

    pub struct Maker;
    impl MakeWriter<'_> for Maker {
        type Writer = W;
        fn make_writer(&self) -> Self::Writer {
            W
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // Default: our own info logs, but silence the sniffer's chatty
            // KCP warnings (harmless mid-stream reassembly noise, e.g.
            // duplicated packets seen at multiple capture components).
            "warn,auto_artifactarium::kcp=off,genshin_mora_reader=info"
                .into()
        });
    #[cfg(not(debug_assertions))]
    {
        if let Some(base) = std::env::var_os("LOCALAPPDATA") {
            log_file::open(
                &std::path::PathBuf::from(base)
                    .join("GenshinReader")
                    .join("app.log"),
            );
        }
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(log_file::Maker)
            .init();
    }
    #[cfg(debug_assertions)]
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn run_capture(ledger_path: PathBuf, no_elevate: bool, stats: bool) -> Result<()> {
    init_tracing();

    // Packet capture via ETW needs elevation.
    if !admin::is_elevated() {
        if no_elevate {
            anyhow::bail!("packet capture requires admin rights — rerun elevated (or without --no-elevate)");
        }
        println!("Requesting administrator rights (needed for packet capture)...");
        admin::relaunch_elevated()?;
        println!("Elevated instance launched; this window can be closed.");
        return Ok(());
    }

    let keys = load_keys()?;
    let mut sniffer = GameSniffer::new().set_initial_keys(keys);
    let mut ledger = ledger::Ledger::open(&ledger_path)
        .with_context(|| format!("opening ledger at {}", ledger_path.display()))?;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║               GenshinReader — Mora tracker               ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("Ledger: {}", ledger.current_path().display());
    println!();
    println!("Now: launch Genshin Impact and log in (walk through the door).");
    println!("The encryption key can only be captured during login, so the");
    println!("game session must START while this tool is running.");
    println!("VPN users (e.g. Speedify): run with --stats to verify packets");
    println!("are being seen; keep the VPN connected the whole session.");
    println!();
    println!("Waiting for traffic... (Ctrl+C to stop)");
    println!();

    ledger.new_session();

    let mut frames = capture::start_capture(stats)?;
    let mut decryption_ok = false;
    let mut commands_seen: u64 = 0;
    let mut console_uid: Option<u32> = None;
    let mut uid_votes: std::collections::HashMap<u32, u32> = Default::default();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("Stopping. {} game commands processed, balance last known: {}",
                    commands_seen,
                    ledger.balance.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into()));
                return Ok(());
            }
            frame = frames.recv() => {
                let Some(frame) = frame else {
                    anyhow::bail!("capture channel closed");
                };
                match sniffer.receive_packet(frame) {
                    Some(GamePacket::Connection(conn)) => match conn {
                        ConnectionPacket::HandshakeRequested => {
                            println!("── new login handshake — session {} ──", ledger.session);
                            ledger.new_session();
                            decryption_ok = false;
                        }
                        ConnectionPacket::Disconnected => {
                            tracing::info!("connection closed");
                        }
                        _ => {}
                    },
                    Some(GamePacket::Commands(commands)) => {
                        // Only treat actually-decrypted commands as proof of
                        // decryption — empty command lists still arrive while
                        // the key exchange is failing.
                        if !decryption_ok && !commands.is_empty() {
                            decryption_ok = true;
                            println!();
                            println!(">>> Decryption established — tracking Mora events. <<<");
                            println!();
                        }
                        commands_seen += commands.len() as u64;
                        for command in &commands {
                            // Per-account ledger separation: PacketHead.user_id
                            // when present, otherwise avatar-scene UID votes
                            // (the login token's account id spans multiple
                            // regions, so it is never used as the UID).
                            if console_uid.is_none() {
                                let from_head =
                                    auto_artifactarium::r#gen::protos::PacketHead::parse_from_bytes(
                                        &command.proto_header,
                                    )
                                    .ok()
                                    .filter(|h| h.user_id != 0)
                                    .map(|h| h.user_id);
                                if let Some(uid) = from_head {
                                    console_uid = Some(uid);
                                    ledger.set_uid(uid);
                                    println!(
                                        "Account UID {uid} — ledger: {}",
                                        ledger.current_path().display()
                                    );
                                } else {
                                    detect::detect_uid_candidates(command, &mut uid_votes);
                                    if let Some((&best, &count)) =
                                        uid_votes.iter().max_by_key(|(_, c)| **c)
                                    {
                                        if count >= 3 {
                                            console_uid = Some(best);
                                            ledger.set_uid(best);
                                            println!(
                                                "In-game UID {best} identified — ledger: {}",
                                                ledger.current_path().display()
                                            );
                                        }
                                    }
                                }
                            }
                            for event in detect::detect_mora_events(command) {
                                record_event(&mut ledger, &event);
                            }
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

fn record_event(ledger: &mut ledger::Ledger, event: &MoraEvent) {
    tracing::debug!(?event, "mora event");
    let row = ledger.record(event);
    ledger::print_live(&row);
}

fn run_summary(
    ledger_path: PathBuf,
    date: Option<String>,
    all: bool,
    csv: Option<PathBuf>,
    clipboard: bool,
    uid: Option<u32>,
) -> Result<()> {
    let filter = if all {
        None
    } else {
        let date = match date {
            Some(d) => chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d")
                .with_context(|| format!("parsing date '{d}' (expected YYYY-MM-DD)"))?,
            None => chrono::Local::now().date_naive(),
        };
        Some(date)
    };

    let events = ledger::load_events(&ledger_path, filter)?;
    let rows = ledger::dedupe(&events);
    let config = ledger::ExportConfig::load(
        ledger_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
    );
    let title = match (&filter, uid) {
        (Some(d), Some(uid)) => format!("{} (UID {uid})", d.format("%Y-%m-%d")),
        (Some(d), None) => d.format("%Y-%m-%d").to_string(),
        (None, Some(uid)) => format!("all time (UID {uid})"),
        (None, None) => "all time".to_string(),
    };

    ledger::print_summary(&rows, &title);

    if rows.is_empty() {
        println!("\n(No Mora events recorded for this period.)");
    }

    if let Some(csv_path) = csv {
        ledger::write_csv(&rows, &csv_path, &config)?;
    }
    if clipboard {
        ledger::copy_clipboard(&rows, &config)?;
    }

    Ok(())
}
