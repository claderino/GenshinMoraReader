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
use crate::detect::MoraEvent;
use crate::ledger::{self, ExportConfig, LedgerEvent};

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
        // Gadget id tracking for chest-tier resolution (see the command
        // loop below).
        let mut gadget_ids: std::collections::HashMap<u64, u64> =
            Default::default();
        let mut config_ids: std::collections::HashMap<u64, u64> =
            Default::default();
        let mut last_chest_gadget: Option<(u64, std::time::Instant)> = None;
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

                        // Gadget id tracking for chest-tier resolution:
                        // entity id and scene-local config id → gadget
                        // family id (27685 appears), plus the interact /
                        // world-chest-open signals that correlate with
                        // chest ItemAdds to resolve the exact tier.
                        for (eid, cfg, gid) in
                            detect::detect_gadget_ids(command)
                        {
                            gadget_ids.insert(eid, gid);
                            if cfg != 0 {
                                config_ids.insert(cfg, gid);
                            }
                        }
                        if gadget_ids.len() > 65_536 {
                            gadget_ids.clear();
                            config_ids.clear();
                        }
                        if let Some((_entity, ity)) =
                            detect::detect_gadget_interact_entity(command)
                        {
                            // Only chest-family interacts (3 =
                            // OPEN_CHEST, 8 = GENERAL_REWARD) —
                            // PICK_ITEM/GATHER noise must not drive the
                            // tier correlation.
                            if matches!(ity, 3 | 8) {
                                if let Some(gid) =
                                    gadget_ids.get(&_entity).copied()
                                {
                                    last_chest_gadget = Some((
                                        gid,
                                        std::time::Instant::now(),
                                    ));
                                }
                            }
                        }
                        // WorldChestOpenNotify: the authoritative
                        // chest-open moment — resolves locked chests
                        // whose F-press interact happened long before
                        // the loot landed.
                        if let Some(cfg) =
                            detect::detect_world_chest_config(command)
                        {
                            if let Some(gid) =
                                config_ids.get(&cfg).copied()
                            {
                                tracing::info!(
                                    gadget_id = gid,
                                    "world chest open resolved"
                                );
                                last_chest_gadget = Some((
                                    gid,
                                    std::time::Instant::now(),
                                ));
                            }
                        }

                        for mut event in detect::detect_mora_events(command) {
                            // Attach the recent gadget id to chest-family
                            // ItemAdds for tier labeling.
                            if let MoraEvent::ItemAdd {
                                action_reason: Some(r),
                                ref mut gadget_id,
                                ..
                            } = event
                            {
                                if matches!(r, 39) {
                                    if let Some((gid, t)) =
                                        last_chest_gadget
                                    {
                                        if t.elapsed()
                                            < std::time::Duration::from_millis(
                                                8000,
                                            )
                                        {
                                            *gadget_id = Some(gid);
                                            tracing::info!(
                                                gadget_id = gid,
                                                age_ms = t
                                                    .elapsed()
                                                    .as_millis()
                                                    as u64,
                                                "chest tier resolved"
                                            );
                                        }
                                    }
                                }
                            }
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

    export_config: ledger::ExportConfig,
    show_settings: bool,
    /// Reason labels available for mapping (from current rows).
    mappable_reasons: Vec<String>,
    /// Per-view CSV export markers (view key → newest exported ts_ms):
    /// after an export, the table can show only newer events.
    export_markers: std::collections::HashMap<String, i64>,
    /// When true, rows are filtered to events newer than the last
    /// export marker for the current view.
    since_export: bool,
    /// Unsaved description edits (flushed to export.json on focus loss).
    export_dirty: bool,

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
            export_config: ledger::ExportConfig::load(&ledger_dir),
            show_settings: false,
            mappable_reasons: Vec::new(),
            export_markers: Self::load_export_markers(&ledger_dir),
            since_export: true,
            export_dirty: false,
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

    /// Key identifying the current view in the export markers
    /// ("all" or the active uid).
    fn view_key(&self) -> String {
        match (self.view_all, self.active_uid) {
            (false, Some(uid)) => uid.to_string(),
            _ => "all".into(),
        }
    }

    fn markers_path() -> std::path::PathBuf {
        // beside the ledger files
        std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_default()
            .join("GenshinReader")
            .join("export_markers.json")
    }

    fn load_export_markers(
        dir: &std::path::Path,
    ) -> std::collections::HashMap<String, i64> {
        // Prefer the marker file beside the ledger dir (portable);
        // fall back to LOCALAPPDATA.
        let beside = dir.join("export_markers.json");
        let path = if beside.exists() {
            beside
        } else {
            Self::markers_path()
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Default::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    fn save_export_markers(&self) {
        let beside = self.ledger_dir.join("export_markers.json");
        let path = if beside.parent().map(|p| p.exists()).unwrap_or(false)
        {
            beside
        } else {
            Self::markers_path()
        };
        if let Ok(json) = serde_json::to_string(&self.export_markers) {
            let _ = std::fs::write(path, json);
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
        let mut rows = ledger::dedupe(&self.events);
        // Live chest-label resolution: user gadget mappings (settings)
        // override the built-in table and apply retroactively —
        // stored rows keep the plain label; presentation resolves.
        for row in rows.iter_mut() {
            if let Some(gid) = row.gadget_id {
                if let Some(label) =
                    ledger::resolve_chest_label(gid, &self.export_config)
                {
                    row.reason = label;
                }
            }
        }
        // "Since last export" filter: only events strictly newer than
        // the newest row the last CSV export covered for this view.
        if self.since_export {
            let key = self.view_key();
            if let Some(&marker) = self.export_markers.get(&key) {
                rows.retain(|r| r.ts_ms > marker);
            }
        }
        self.rows = rows;
        self.earned = self.rows.iter().filter(|r| r.amount > 0).map(|r| r.amount).sum();
        self.spent = self.rows.iter().filter(|r| r.amount < 0).map(|r| -r.amount).sum();

        // Latest known balance (fall back to older snapshots if any).
        self.balance = self.events.iter().rev().find_map(|e| e.balance);

        // Distinct reason labels available for mapping.
        let mut reasons: Vec<String> = self.rows.iter().map(|r| r.reason.clone()).collect();
        reasons.sort();
        reasons.dedup();
        self.mappable_reasons = reasons;

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
        match ledger::write_csv(&self.rows, &path, &self.export_config) {
            Ok(()) => {
                // Record the export marker: everything in self.rows is
                // now exported — future views (with the since-export
                // filter on) start after the newest exported row.
                if let Some(newest) =
                    self.rows.iter().map(|r| r.ts_ms).max()
                {
                    let key = self.view_key();
                    let prev = self.export_markers.get(&key).copied();
                    if prev.is_none_or(|p| newest > p) {
                        self.export_markers.insert(key, newest);
                        self.save_export_markers();
                    }
                }
                self.toast =
                    Some(format!("Exported {}", path.display()));
            }
            Err(e) => self.toast = Some(format!("Export failed: {e}")),
        }
    }

    fn copy_clipboard(&mut self) {
        match ledger::copy_clipboard(&self.rows, &self.export_config) {
            Ok(()) => self.toast = Some("Copied rows — paste into your spreadsheet".into()),
            Err(e) => self.toast = Some(format!("Clipboard failed: {e}")),
        }
    }

    /// The export-settings window. Returns true while open.
    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut stay_open = self.show_settings;
        egui::Window::new("⚙ Export settings")
            .open(&mut stay_open)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.heading("Timestamp format");
                ui.horizontal(|ui| {
                    ui.label("Format:");
                    ui.text_edit_singleline(&mut self.export_config.datetime_format);
                });
                ui.horizontal(|ui| {
                    if ui.button("Excel serial").clicked() {
                        self.export_config.datetime_format = "excel".into();
                    }
                    if ui.button("2026-10-08 14:30:05").clicked() {
                        self.export_config.datetime_format = "%Y-%m-%d %H:%M:%S".into();
                    }
                    if ui.button("ISO").clicked() {
                        self.export_config.datetime_format = "%Y-%m-%dT%H:%M:%S".into();
                    }
                });
                let now_ms = chrono::Local::now().timestamp_millis();
                ui.small(format!(
                    "preview: {}",
                    self.export_config.format_ts(now_ms)
                ));
                ui.add_space(6.0);

                ui.heading("Columns");
                let mut columns = self.export_config.columns.join(", ");
                ui.text_edit_singleline(&mut columns);
                if ui.button("Apply columns").clicked() {
                    self.export_config.columns = columns
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                ui.horizontal(|ui| {
                    if ui
                        .button("Default (timestamp, uid, action, …)")
                        .clicked()
                    {
                        self.export_config.columns = ExportConfig::default().columns;
                    }
                    if ui
                        .button("Spreadsheet (type, amount, remaining, date, description)")
                        .clicked()
                    {
                        self.export_config.columns = ["type", "amount", "remaining", "date", "description"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                    }
                });
                ui.small(
                    "available: timestamp, date, type, action, amount, remaining (= amount), \
                     balance, uid, description (empty, hand-filled), source",
                );
                ui.checkbox(&mut self.export_config.include_header, "Include header row");
                ui.add_space(6.0);

                ui.heading("Reason mappings");
                ui.small("Exported type ← tracker label (empty = passthrough)");
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .show(ui, |ui| {
                        let mut remove: Option<String> = None;
                        for (label, value) in self.export_config.reason_map.clone() {
                            ui.horizontal(|ui| {
                                ui.label(&label);
                                ui.label("→");
                                let mut value = value;
                                ui.text_edit_singleline(&mut value);
                                if ui.button("✖").clicked() {
                                    remove = Some(label.clone());
                                }
                                self.export_config
                                    .reason_map
                                    .insert(label.clone(), value);
                            });
                        }
                        if let Some(label) = remove {
                            self.export_config.reason_map.remove(&label);
                        }
                    });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.menu_button("＋ Add label…", |ui| {
                        for reason in self.mappable_reasons.clone() {
                            if !self.export_config.reason_map.contains_key(&reason) {
                                if ui.button(&reason).clicked() {
                                    self.export_config
                                        .reason_map
                                        .insert(reason.clone(), String::new());
                                    ui.close_menu();
                                }
                            }
                        }
                        if self.mappable_reasons.is_empty() {
                            ui.weak("(no rows loaded yet)");
                        }
                    });
                    if ui.button("Map all unmapped to…").clicked() {
                        // no-op placeholder; label mapping via Add label
                    }
                });
                ui.add_space(6.0);

                ui.heading("Gadget labels");
                ui.small("Chest gadget id → label (overrides the built-in tier table; applies to past rows too)");
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .show(ui, |ui| {
                        let mut remove: Option<String> = None;
                        for (id, label) in
                            self.export_config.gadget_labels.clone()
                        {
                            ui.horizontal(|ui| {
                                ui.monospace(&id);
                                ui.label("→");
                                let mut label = label;
                                ui.text_edit_singleline(&mut label);
                                if ui.button("✖").clicked() {
                                    remove = Some(id.clone());
                                }
                                self.export_config
                                    .gadget_labels
                                    .insert(id.clone(), label);
                            });
                        }
                        if let Some(id) = remove {
                            self.export_config.gadget_labels.remove(&id);
                            self.refresh();
                        }
                    });
                // Recently seen gadget ids without any label (from the
                // loaded rows) — one click adds a pre-filled entry.
                let unlabeled: Vec<u64> = {
                    let mut seen =
                        std::collections::BTreeSet::new();
                    for r in &self.rows {
                        if let Some(gid) = r.gadget_id {
                            if !self
                                .export_config
                                .gadget_labels
                                .contains_key(&gid.to_string())
                                && ledger::resolve_chest_label(
                                    gid,
                                    &self.export_config,
                                )
                                .is_none()
                            {
                                seen.insert(gid);
                            }
                        }
                    }
                    seen.into_iter().collect()
                };
                ui.horizontal(|ui| {
                    if !unlabeled.is_empty() {
                        ui.label("Unlabeled seen:");
                        for gid in unlabeled {
                            if ui
                                .button(format!("＋ {gid}"))
                                .on_hover_text(
                                    "map this gadget id",
                                )
                                .clicked()
                            {
                                self.export_config.gadget_labels.insert(
                                    gid.to_string(),
                                    String::new(),
                                );
                            }
                        }
                    } else {
                        ui.weak("(no unlabeled gadget ids in view)");
                    }
                    let mut new_id = String::new();
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut new_id)
                            .hint_text("gadget id…"),
                    );
                    if resp.lost_focus()
                        && new_id.trim().parse::<u64>().is_ok()
                    {
                        self.export_config.gadget_labels.insert(
                            new_id.trim().to_string(),
                            String::new(),
                        );
                    }
                });
                ui.add_space(6.0);

                ui.heading("Row preview");
                if let Some(row) = self.rows.last() {
                    let cells = self.export_config.render_row(row);
                    ui.monospace(cells.join("  |  "));
                } else {
                    ui.weak("(no rows yet)");
                }
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        if let Err(e) = self.export_config.save(&self.ledger_dir) {
                            self.toast = Some(format!("Could not save export.json: {e}"));
                        } else {
                            self.toast = Some("Export settings saved".into());
                        }
                    }
                    if ui.button("Reset to defaults").clicked() {
                        self.export_config = ExportConfig::default();
                    }
                });
            });
        self.show_settings = stay_open;
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
                // Since-last-export filter: on by default after the
                // first export; toggling off shows the full day again.
                let has_marker = self
                    .export_markers
                    .contains_key(&self.view_key());
                if has_marker {
                    if ui
                        .checkbox(&mut self.since_export, "🆕 Since last export")
                        .changed()
                    {
                        self.refresh();
                    }
                }
                if ui.button("⚙ Export settings").clicked() {
                    self.show_settings = true;
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

        if self.show_settings {
            self.settings_window(ctx);
        }

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
                .column(Column::initial(160.0))
                .column(Column::remainder())
                .column(Column::exact(88.0))
                .column(Column::initial(120.0))
                .column(Column::exact(64.0))
                .header(24.0, |mut header| {
                    header.col(|ui| { ui.strong("time"); });
                    header.col(|ui| { ui.strong("amount"); });
                    header.col(|ui| { ui.strong("action"); });
                    header.col(|ui| { ui.strong("description"); });
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
                                // Editable per-row description — persisted
                                // into the export config (keyed uid:ts_ms)
                                // and exported via the `description` column.
                                let key = ledger::row_key(item);
                                let buf = self
                                    .export_config
                                    .descriptions
                                    .entry(key)
                                    .or_default();
                                let resp = ui.add(
                                    egui::TextEdit::singleline(buf)
                                        .hint_text("…")
                                        .desired_width(
                                            f32::INFINITY,
                                        ),
                                );
                                if resp.changed() {
                                    self.export_dirty = true;
                                }
                                if resp.lost_focus()
                                    && self.export_dirty
                                {
                                    // Drop empty entries to keep the file
                                    // compact.
                                    self.export_config
                                        .descriptions
                                        .retain(|_, v| !v.is_empty());
                                    let _ = self
                                        .export_config
                                        .save(&self.ledger_dir);
                                    self.export_dirty = false;
                                }
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
