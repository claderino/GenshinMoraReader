//! Native GUI (egui/eframe) for the Mora tracker.
//!
//! The capture pipeline (pktmon → decrypt → detect → ledger) runs on a
//! background thread and forwards recorded events to the UI via a channel.
//! The GUI is the default when the exe is launched without arguments.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use anyhow::{Context, Result};
use auto_artifactarium::r#gen::protos::PacketHead;
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use protobuf::Message;

use crate::capture;
use crate::detect;
use crate::ledger::{self, LedgerEvent};

#[derive(Debug)]
pub enum WorkerMsg {
    Info(String),
    Error(String),
    Decrypting(bool),
    Uid(u32),
    Event(LedgerEvent),
}

/// Launch the GUI. Blocks until the window is closed.
pub fn run(ledger_path: PathBuf) -> Result<()> {
    // Mirror library/app logs into a file so capture problems can be
    // diagnosed after the fact without rerunning a special debug build.
    let log_path = ledger_path
        .parent()
        .map(|p| p.join("reader.log"))
        .unwrap_or_else(|| PathBuf::from("reader.log"));
    if let Some(dir) = log_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();
    if let Some(file) = log_file {
        let file = std::sync::Arc::new(std::sync::Mutex::new(file));
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    "info,auto_artifactarium::kcp=warn,genshin_mora_reader=info".into()
                }),
            )
            .with_writer(move || {
                let clone = match file.lock() {
                    Ok(guard) => guard.try_clone(),
                    Err(poisoned) => poisoned.into_inner().try_clone(),
                };
                match clone {
                    Ok(f) => Box::new(std::io::BufWriter::new(f)) as Box<dyn std::io::Write>,
                    Err(_) => Box::new(std::io::sink()),
                }
            })
            .with_ansi(false)
            .init();
    }

    let (tx, rx) = channel::<WorkerMsg>();

    let worker_ledger = ledger_path.clone();
    std::thread::Builder::new()
        .name("mora-capture".into())
        .spawn(move || {
            if let Err(e) = worker_main(worker_ledger, tx.clone()) {
                let _ = tx.send(WorkerMsg::Error(format!("{e:#}")));
            }
        })
        .context("spawning capture worker")?;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 640.0])
            .with_min_inner_size([720.0, 430.0])
            .with_title("GenshinReader — Mora tracker"),
        ..Default::default()
    };

    eframe::run_native(
        "GenshinReader",
        options,
        Box::new(move |_cc| Ok(Box::new(MoraApp::new(ledger_path, rx)))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}

// ---------------------------------------------------------------------------
// Background worker: owns the capture pipeline
// ---------------------------------------------------------------------------

fn worker_main(ledger_path: PathBuf, tx: Sender<WorkerMsg>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating worker runtime")?;

    rt.block_on(async move {
        let keys = crate::load_keys()?;
        let mut sniffer = auto_artifactarium::GameSniffer::new().set_initial_keys(keys);
        let mut ledger = ledger::Ledger::open(&ledger_path)?;
        ledger.new_session();

        let _ = tx.send(WorkerMsg::Info(
            "Listening on UDP 22101/22102 — start the game and log in".into(),
        ));

        let mut frames = capture::start_capture(false)?;
        let mut decryption_ok = false;
        let mut uid: Option<u32> = None;
        let mut head_samples: u32 = 0;

        // In-game UID discovery: avatar-scene packets carry the player's UID
        // (9 digits) — votes accumulate until one is confident. The login
        // token's account id is NOT used for file naming: one account spans
        // multiple regions, each with its own UID.
        let mut uid_votes: std::collections::HashMap<u32, u32> = Default::default();
        let mut uid_locked = false;

        // Watchdog state: if a login handshake was seen but no commands
        // decrypt shortly after, prompt the user to relogin once.
        let mut handshake_at: Option<std::time::Instant> = None;
        let mut hint_shown = false;

        loop {
            let frame = tokio::select! {
                frame = frames.recv() => match frame {
                    Some(frame) => frame,
                    None => anyhow::bail!("capture channel closed"),
                },
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    if let Some(at) = handshake_at {
                        if !decryption_ok
                            && !hint_shown
                            && at.elapsed() > Duration::from_secs(15)
                        {
                            hint_shown = true;
                            let _ = tx.send(WorkerMsg::Info(
                                "Login detected, but the session key could not be derived. \
                                 This happens on the fast-relogin path (7.1 key change). \
                                 Fully exit and relaunch the game — cold-start logins track fine."
                                    .into(),
                            ));
                        }
                    }
                    continue;
                }
            };

            match sniffer.receive_packet(frame) {
                Some(auto_artifactarium::GamePacket::Connection(conn)) => {
                    if let auto_artifactarium::ConnectionPacket::HandshakeRequested = conn {
                        ledger.new_session();
                        decryption_ok = false;
                        uid = None;
                        handshake_at = Some(std::time::Instant::now());
                        hint_shown = false;
                        let _ = tx.send(WorkerMsg::Decrypting(false));
                        let _ = tx.send(WorkerMsg::Info(
                            "New login handshake — waiting for session key".into(),
                        ));
                    }
                }
                Some(auto_artifactarium::GamePacket::Commands(commands)) => {
                    // Only treat actually-decrypted commands as "tracking" —
                    // the sniffer also emits empty command lists while the
                    // key exchange is still failing.
                    if !decryption_ok && !commands.is_empty() {
                        decryption_ok = true;
                        head_samples = 12;
                        let _ = tx.send(WorkerMsg::Decrypting(true));
                        let _ = tx.send(WorkerMsg::Info(
                            "Tracking — key captured, decrypting game traffic".into(),
                        ));
                    }
                    for command in &commands {
                        // Identify the account: prefer PacketHead.user_id if
                        // the version populates it…
                        if uid.is_none() {
                            if let Ok(head) = PacketHead::parse_from_bytes(&command.proto_header)
                            {
                                if head.user_id != 0 {
                                    uid = Some(head.user_id);
                                    ledger.set_uid(head.user_id);
                                    let _ = tx.send(WorkerMsg::Uid(head.user_id));
                                }
                            }
                        }

                        // Vote for the in-game UID from avatar-scene packets.
                        if !uid_locked {
                            detect::detect_uid_candidates(command, &mut uid_votes);
                        }

                        // Header forensics: sample the first few session
                        // command headers so the real 7.x PacketHead layout
                        // can be analyzed from reader.log.
                        if head_samples > 0 {
                            head_samples -= 1;
                            let hex: String =
                                command.proto_header.iter().map(|b| format!("{b:02x}")).collect();
                            let head_info = PacketHead::parse_from_bytes(&command.proto_header)
                                .map(|h| {
                                    format!(
                                        "packet_id={} rpc_id={} seq={} sent_ms={} user_id={} session_id={}",
                                        h.packet_id, h.rpc_id, h.client_sequence_id, h.sent_ms, h.user_id, h.user_session_id
                                    )
                                })
                                .unwrap_or_else(|e| format!("parse error: {e}"));
                            tracing::info!(
                                command_id = command.command_id,
                                header_hex = %hex,
                                head = %head_info,
                                "session head sample"
                            );
                        }

                        for event in detect::detect_mora_events(command) {
                            let row = ledger.record(&event);
                            let _ = tx.send(WorkerMsg::Event(row));
                        }
                    }

                    // The token's account id is informational only — one
                    // account spans multiple regions with distinct UIDs, so
                    // the ledger waits for the avatar-scene votes.
                    if uid.is_none() && sniffer.account_uid().is_some() {
                        let _ = tx.send(WorkerMsg::Info(
                            "Logged in — identifying in-game UID…".into(),
                        ));
                    }

                    // Identify the in-game UID from avatar-scene votes (the
                    // only reliable source on 7.x); events buffer until then.
                    if !uid_locked {
                        let winner = uid_votes
                            .iter()
                            .max_by_key(|(_, count)| **count)
                            .filter(|(_, count)| **count >= 3)
                            .map(|(u, _)| *u);
                        if let Some(real) = winner {
                            ledger.set_uid(real);
                            uid = Some(real);
                            uid_locked = true;
                            let _ = tx.send(WorkerMsg::Uid(real));
                            let _ = tx.send(WorkerMsg::Info(format!(
                                "In-game UID {real} identified — ledger {}",
                                ledger.current_path().display()
                            )));
                        }
                    }
                }
                None => {}
            }
        }
    })
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

struct MoraApp {
    ledger_path: PathBuf,
    ledger_dir: PathBuf,
    rx: Receiver<WorkerMsg>,

    /// Which account's history the table shows.
    view_all: bool,
    active_uid: Option<u32>,
    known_uids: Vec<u32>,

    events: Vec<LedgerEvent>,
    rows: Vec<ledger::SummaryRow>,
    by_action: Vec<(String, i64, i64)>,

    balance: Option<i64>,
    decrypting: bool,
    status: String,
    error: Option<String>,
    earned: i64,
    spent: i64,

    toast: Option<String>,
}

impl MoraApp {
    fn new(ledger_path: PathBuf, rx: Receiver<WorkerMsg>) -> Self {
        let ledger_dir = ledger_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let mut app = Self {
            ledger_path,
            ledger_dir: ledger_dir.clone(),
            rx,
            view_all: true,
            active_uid: None,
            known_uids: ledger::discover_uids(&ledger_dir),
            events: Vec::new(),
            rows: Vec::new(),
            by_action: Vec::new(),
            balance: None,
            decrypting: false,
            status: "Starting…".into(),
            error: None,
            earned: 0,
            spent: 0,
            toast: None,
        };
        app.reload_history();
        app
    }

    fn ledger_file(&self, uid: Option<u32>) -> PathBuf {
        match uid {
            Some(uid) => self.ledger_dir.join(format!("mora_{uid}.jsonl")),
            None => self.ledger_path.clone(),
        }
    }

    fn reload_history(&mut self) {
        let today = chrono::Local::now().date_naive();
        let mut events = Vec::new();
        if self.view_all {
            events.extend(
                ledger::load_events(&self.ledger_path, Some(today)).unwrap_or_default(),
            );
            for uid in &self.known_uids {
                events.extend(
                    ledger::load_events(&self.ledger_file(Some(*uid)), Some(today))
                        .unwrap_or_default(),
                );
            }
        } else if let Some(uid) = self.active_uid {
            events.extend(
                ledger::load_events(&self.ledger_file(Some(uid)), Some(today)).unwrap_or_default(),
            );
        }
        self.events = events;
        self.refresh();
    }

    fn refresh(&mut self) {
        self.rows = ledger::dedupe(&self.events);
        self.earned = self.rows.iter().filter(|r| r.amount > 0).map(|r| r.amount).sum();
        self.spent = self.rows.iter().filter(|r| r.amount < 0).map(|r| -r.amount).sum();

        // Latest known balance (fall back to older snapshots if any).
        self.balance = self.events.iter().rev().find_map(|e| e.balance);

        let mut map: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
        for row in &self.rows {
            let entry = map.entry(row.reason.clone()).or_default();
            if row.amount >= 0 {
                entry.0 += row.amount;
            } else {
                entry.1 += -row.amount;
            }
        }
        let mut by_action: Vec<_> = map.into_iter().map(|(k, (e, s))| (k, e, s)).collect();
        by_action.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));
        self.by_action = by_action;
    }

    fn apply(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Info(text) => self.status = text,
            WorkerMsg::Error(text) => self.error = Some(text),
            WorkerMsg::Decrypting(ok) => {
                self.decrypting = ok;
                if ok {
                    self.status = "Tracking — key captured, decrypting game traffic".into();
                }
            }
            WorkerMsg::Uid(uid) => {
                if !self.known_uids.contains(&uid) {
                    self.known_uids.push(uid);
                    self.known_uids.sort();
                }
                // Follow the account that is currently logged in.
                self.active_uid = Some(uid);
                self.view_all = false;
                self.reload_history();
            }
            WorkerMsg::Event(row) => {
                // Live events only extend the table when they belong to the
                // account currently in view (or the view is "all").
                let matches_view = self.view_all || row.uid == self.active_uid;
                self.events.push(row);
                if matches_view {
                    self.refresh();
                }
            }
        }
    }

    fn export_csv(&mut self) {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let uid_part = match (self.view_all, self.active_uid) {
            (false, Some(uid)) => format!("{uid}-"),
            _ => String::new(),
        };
        let mut path = self.ledger_dir.clone();
        path.push(format!("mora-{uid_part}{stamp}.csv"));
        match ledger::write_csv(&self.rows, &path) {
            Ok(()) => self.toast = Some(format!("Exported {}", path.display())),
            Err(e) => self.toast = Some(format!("Export failed: {e}")),
        }
    }

    fn copy_clipboard(&mut self) {
        match ledger::copy_clipboard(&self.rows) {
            Ok(()) => self.toast = Some("Copied rows — paste into your spreadsheet".into()),
            Err(e) => self.toast = Some(format!("Clipboard failed: {e}")),
        }
    }
}

impl eframe::App for MoraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain worker messages.
        while let Ok(msg) = self.rx.try_recv() {
            self.apply(msg);
        }
        ctx.request_repaint_after(Duration::from_millis(400));

        // Toast auto-clear.
        if let Some(toast) = &self.toast {
            if toast.starts_with("Copied") {
                // keep a little longer
            }
        }

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let (color, label) = if let Some(err) = &self.error {
                    let short = err.lines().next().unwrap_or("error");
                    (egui::Color32::from_rgb(230, 110, 110), format!("● error: {short}"))
                } else if self.decrypting {
                    (egui::Color32::from_rgb(110, 210, 130), "● tracking".to_string())
                } else {
                    (egui::Color32::from_rgb(230, 190, 90), "● waiting for login".to_string())
                };
                ui.colored_label(color, label);

                ui.separator();

                ui.strong(
                    self.balance
                        .map(|b| format!("{} Mora", thousands(b)))
                        .unwrap_or_else(|| "balance unknown".into()),
                );

                ui.separator();

                // Current account — filled in shortly after a tracked login.
                if let Some(uid) = self.active_uid {
                    ui.strong(format!("UID {uid}"));
                } else {
                    ui.weak("UID: appears after login");
                }

                ui.separator();

                let net = self.earned - self.spent;
                ui.label(format!(
                    "today: +{} / −{} (net {net:+})",
                    thousands(self.earned),
                    thousands(self.spent)
                ));

                // Account selector (once at least one UID is known).
                if !self.known_uids.is_empty() {
                    ui.separator();
                    let current = if self.view_all {
                        "all accounts".to_string()
                    } else {
                        self.active_uid
                            .map(|u| u.to_string())
                            .unwrap_or_else(|| "all accounts".into())
                    };
                    egui::ComboBox::from_id_salt("account")
                        .selected_text(&current)
                        .width(120.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.view_all, true, "all accounts");
                            if self.view_all {
                                self.reload_history();
                            }
                            let uids = self.known_uids.clone();
                            for uid in uids {
                                let selected = !self.view_all && self.active_uid == Some(uid);
                                if ui.selectable_label(selected, uid.to_string()).clicked() {
                                    self.active_uid = Some(uid);
                                    self.view_all = false;
                                    self.reload_history();
                                }
                            }
                        });
                }
            });
            ui.add_space(2.0);
            ui.small(egui::RichText::new(&self.status).weak());
            if let Some(toast) = &self.toast {
                ui.small(egui::RichText::new(toast).color(egui::Color32::from_rgb(110, 200, 150)));
            }
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("actions").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📋 Copy for spreadsheet").clicked() {
                    self.copy_clipboard();
                }
                if ui.button("💾 Export CSV").clicked() {
                    self.export_csv();
                }
                if ui.button("↻ Reload history").clicked() {
                    self.reload_history();
                }
                if ui.button("📂 Open ledger folder").clicked() {
                    if let Some(dir) = self.ledger_path.parent() {
                        let _ = std::process::Command::new("explorer").arg(dir).spawn();
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(format!("{}", self.ledger_path.display()));
                });
            });
            ui.add_space(4.0);
        });

        if !self.by_action.is_empty() {
            egui::TopBottomPanel::top("by_action")
                .resizable(false)
                .show(ctx, |ui| {
                    egui::CollapsingHeader::new("By action (today)")
                        .default_open(false)
                        .show(ui, |ui| {
                            egui::Grid::new("by_action_grid")
                                .num_columns(3)
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.strong("action");
                                    ui.strong("earned");
                                    ui.strong("spent");
                                    ui.end_row();
                                    for (reason, earned, spent) in self.by_action.iter().take(12) {
                                        ui.label(reason);
                                        ui.monospace(format!("+{}", thousands(*earned)));
                                        ui.monospace(format!("−{}", thousands(*spent)));
                                        ui.end_row();
                                    }
                                });
                        });
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(84.0))
                .column(Column::exact(92.0))
                .column(Column::remainder())
                .column(Column::exact(88.0))
                .column(Column::initial(120.0))
                .column(Column::exact(64.0))
                .header(24.0, |mut header| {
                    header.col(|ui| { ui.strong("time"); });
                    header.col(|ui| { ui.strong("amount"); });
                    header.col(|ui| { ui.strong("action"); });
                    header.col(|ui| { ui.strong("uid"); });
                    header.col(|ui| { ui.strong("balance after"); });
                    header.col(|ui| { ui.strong("src"); });
                })
                .body(|mut body| {
                    // Newest first.
                    for item in self.rows.iter().rev() {
                        body.row(20.0, |mut row| {
                            row.col(|ui| {
                                ui.monospace(egui::RichText::new(&item.time).weak());
                            });
                            row.col(|ui| {
                                let color = if item.amount >= 0 {
                                    egui::Color32::from_rgb(130, 210, 130)
                                } else {
                                    egui::Color32::from_rgb(235, 120, 120)
                                };
                                ui.monospace(
                                    egui::RichText::new(format!("{:+}", thousands_signed(item.amount)))
                                        .color(color)
                                        .strong(),
                                );
                            });
                            row.col(|ui| {
                                ui.label(&item.reason);
                            });
                            row.col(|ui| {
                                ui.monospace(egui::RichText::new(
                                    item.uid.map(|u| u.to_string()).unwrap_or_else(|| "—".into()),
                                ).weak());
                            });
                            row.col(|ui| {
                                ui.monospace(
                                    egui::RichText::new(
                                        item.balance.map(|b| thousands(b)).unwrap_or_default(),
                                    )
                                    .weak(),
                                );
                            });
                            row.col(|ui| {
                                ui.monospace(egui::RichText::new(item.source).weak());
                            });
                        });
                    }
                });

            if self.rows.is_empty() {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new(
                            "No Mora events yet.\n\n\
                             1. Keep this window open\n\
                             2. Launch Genshin Impact and log in (walk through the door)\n\
                             3. Earn Mora — every change appears here instantly",
                        )
                        .weak(),
                    );
                });
            }
        });
    }
}

fn thousands(n: i64) -> String {
    group(n.abs(), false)
}

fn thousands_signed(n: i64) -> String {
    group(n.abs(), n < 0)
}

fn group(abs: i64, negative: bool) -> String {
    let digits = abs.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if negative {
        out.push('-');
    }
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}
