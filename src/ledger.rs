//! Append-only Mora ledger with balance tracking, live console output and
//! CSV/clipboard export helpers.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::detect::MoraEvent;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LedgerEvent {
    /// RFC3339 local timestamp.
    pub ts: String,
    /// Session identifier (changes on each game login handshake).
    pub session: String,
    /// `prop_change` | `item_add` | `balance` | `session_start`
    pub kind: String,
    /// Signed Mora delta (earned = positive, spent = negative).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    /// Balance after this event, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<i64>,
    /// Reason label (e.g. "Monster kill", "Chest", "Quest reward").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Raw reason enum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_raw: Option<u32>,
    /// Account UID this event belongs to (from PacketHead.user_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Wire command id (diagnostics; scrambled per game version).
    pub command_id: u16,
}

pub struct Ledger {
    /// Directory holding the ledger files (per-UID files live beside the default).
    dir: PathBuf,
    /// Fallback path used when no UID has been identified for a session.
    default_path: PathBuf,
    writer: Option<std::io::BufWriter<File>>,
    writer_path: PathBuf,
    pub session: String,
    pub balance: Option<i64>,
    pub uid: Option<u32>,
    /// Events recorded before the session's UID is known; flushed into the
    /// UID's file as soon as it is identified.
    pending: Vec<LedgerEvent>,
    events_this_session: u64,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self> {
        let dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating ledger directory {}", dir.display()))?;
        Ok(Self {
            writer: None,
            writer_path: path.to_path_buf(),
            dir,
            default_path: path.to_path_buf(),
            session: new_session_id(),
            balance: None,
            uid: None,
            pending: Vec::new(),
            events_this_session: 0,
        })
    }

    /// Ledger file path for a given UID (or the default mixed file).
    pub fn path_for_uid(&self, uid: Option<u32>) -> PathBuf {
        match uid {
            Some(uid) => self.dir.join(format!("mora_{uid}.jsonl")),
            None => self.default_path.clone(),
        }
    }

    /// Path currently being written to (per-UID file once known).
    pub fn current_path(&self) -> &Path {
        &self.writer_path
    }

    /// Identify the account for the current session. Buffered events are
    /// flushed into the account's ledger file.
    pub fn set_uid(&mut self, uid: u32) {
        if self.uid == Some(uid) {
            return;
        }
        self.uid = Some(uid);
        let path = self.path_for_uid(Some(uid));
        self.writer = None; // reopened lazily on next write
        self.writer_path = path;
        let pending = std::mem::take(&mut self.pending);
        for mut event in pending {
            event.uid = Some(uid);
            let _ = self.write(&event);
        }
    }

    /// Start a fresh session (called on game handshake).
    pub fn new_session(&mut self) {
        // Any unattributed events from the previous session go to the
        // default file so nothing is lost.
        if self.uid.is_none() && !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.writer = None;
            self.writer_path = self.default_path.clone();
            for event in pending {
                let _ = self.write(&event);
            }
        }
        self.session = new_session_id();
        self.events_this_session = 0;
        let _ = self.write(&LedgerEvent {
            ts: Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            session: self.session.clone(),
            kind: "session_start".into(),
            amount: None,
            balance: self.balance,
            reason: None,
            reason_raw: None,
            uid: self.uid,
            command_id: 0,
        });
    }

    /// Record a detected event. Returns the persisted row.
    pub fn record(&mut self, event: &MoraEvent) -> LedgerEvent {
        let now = Local::now();
        let (kind, amount, reason, reason_raw) = match event {
            MoraEvent::PropChange { old, new, prop_reason, .. } => {
                let amount = (new - old).round() as i64;
                // Keep our tracked balance anchored to the server's numbers.
                self.balance = Some(new.round() as i64);
                (
                    "prop_change".to_string(),
                    Some(amount),
                    prop_reason
                        .map(|r| crate::reasons::prop_change_reason_name(r).unwrap_or("Unknown").to_string()),
                    *prop_reason,
                )
            }
            MoraEvent::ItemAdd { count, action_reason, .. } => (
                "item_add".to_string(),
                Some(*count as i64),
                action_reason.map(crate::reasons::action_reason_label),
                *action_reason,
            ),
            MoraEvent::Balance { balance, .. } => {
                let new_balance = balance.round() as i64;
                let amount = self.balance.map(|old| new_balance - old);
                self.balance = Some(new_balance);
                ("balance".to_string(), amount, None, None)
            }
        };

        let row = LedgerEvent {
            ts: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            session: self.session.clone(),
            kind,
            amount,
            balance: self.balance,
            reason,
            reason_raw,
            uid: self.uid,
            command_id: event.command_id(),
        };

        if self.uid.is_none() {
            // Hold until the account is identified (usually a second or two
            // into the login burst).
            self.pending.push(row.clone());
            self.events_this_session += 1;
        } else {
            let _ = self.write(&row);
            self.events_this_session += 1;
        }
        row
    }

    fn write(&mut self, event: &LedgerEvent) -> Result<()> {
        if self.writer.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.writer_path)
                .with_context(|| format!("opening ledger {}", self.writer_path.display()))?;
            self.writer = Some(std::io::BufWriter::new(file));
        }
        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        if let Some(writer) = &mut self.writer {
            writer.write_all(line.as_bytes())?;
            writer.flush()?;
        }
        Ok(())
    }
}

/// Discover UIDs that have ledger files in a directory (e.g. for an account
/// selector in the UI).
pub fn discover_uids(dir: &Path) -> Vec<u32> {
    let mut uids = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(uid) = name
                .strip_prefix("mora_")
                .and_then(|s| s.strip_suffix(".jsonl"))
                .and_then(|s| s.parse::<u32>().ok())
            {
                uids.push(uid);
            }
        }
    }
    uids.sort();
    uids
}

fn new_session_id() -> String {
    Local::now().format("%Y%m%d-%H%M%S").to_string()
}

/// Print a live console line for an event.
pub fn print_live(row: &LedgerEvent) {
    let time = row
        .ts
        .split_once('T')
        .map(|(_, rest)| &rest[..8.min(rest.len())])
        .unwrap_or("?");
    match row.kind.as_str() {
        "prop_change" | "item_add" => {
            let amount = row.amount.unwrap_or(0);
            let sign = if amount >= 0 { "+" } else { "-" };
            let reason = row.reason.as_deref().unwrap_or("unknown");
            let kind = if row.kind == "item_add" { "item" } else { "prop" };
            match row.balance {
                Some(balance) => println!(
                    "[{time}] {sign}{} Mora ({reason}) [{kind}]  balance: {}",
                    amount.abs().to_string(),
                    balance.to_string()
                ),
                None => println!("[{time}] {sign}{} Mora ({reason}) [{kind}]", amount.abs()),
            }
        }
        "balance" => {
            if let Some(balance) = row.balance {
                if let Some(amount) = row.amount.filter(|a| *a != 0) {
                    let sign = if amount > 0 { "+" } else { "-" };
                    println!(
                        "[{time}] {sign}{} Mora (balance sync)  balance: {}",
                        amount.abs(),
                        balance
                    );
                } else {
                    println!("[{time}] balance synced: {balance}");
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Summary / export
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SummaryRow {
    /// Event time as unix epoch milliseconds (local display derived from it).
    pub ts_ms: i64,
    pub time: String,
    pub amount: i64,
    pub reason: String,
    pub source: &'static str,
    pub balance: Option<i64>,
    pub uid: Option<u32>,
}

fn ts_to_ms(ts: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}

fn ms_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.with_timezone(&Local).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Load ledger events, optionally filtered to a single local date.
pub fn load_events(path: &Path, date: Option<NaiveDate>) -> Result<Vec<LedgerEvent>> {
    if !path.exists() {
        bail!(
            "No ledger file at {} yet — run a capture session first.",
            path.display()
        );
    }
    let reader = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<LedgerEvent>(line.trim_start_matches('\u{feff}')) {
            Ok(ev) => {
                if let Some(date) = date {
                    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&ev.ts) else {
                        continue;
                    };
                    if parsed.with_timezone(&Local).date_naive() != date {
                        continue;
                    }
                }
                out.push(ev);
            }
            Err(e) => {
                eprintln!("warning: skipping malformed ledger line {}: {e}", i + 1);
            }
        }
    }
    Ok(out)
}

/// Collapse duplicate accounting of the same gain. The server usually sends
/// both an item-add (rich reason) and a prop-change (authoritative balance
/// math) for one action; within a few seconds and for the same amount we
/// merge them into a single row, preferring the richer action reason.
pub fn dedupe(events: &[LedgerEvent]) -> Vec<SummaryRow> {
    struct PropItem {
        ts_ms: i64,
        amount: i64,
        reason: String,
        balance: Option<i64>,
        uid: Option<u32>,
    }
    struct ItemAdd {
        ts_ms: i64,
        amount: i64,
        reason: String,
        balance: Option<i64>,
        uid: Option<u32>,
    }

    let prop_changes: Vec<PropItem> = events
        .iter()
        .filter(|e| e.kind == "prop_change" && e.amount.unwrap_or(0) != 0)
        .map(|e| PropItem {
            ts_ms: ts_to_ms(&e.ts),
            amount: e.amount.unwrap_or(0),
            reason: e
                .reason
                .clone()
                .map(|r| format!("PropChange:{r}"))
                .unwrap_or_else(|| "unknown".into()),
            balance: e.balance,
            uid: e.uid,
        })
        .collect();

    let item_adds: Vec<ItemAdd> = events
        .iter()
        .filter(|e| e.kind == "item_add" && e.amount.unwrap_or(0) != 0)
        .map(|e| ItemAdd {
            ts_ms: ts_to_ms(&e.ts),
            amount: e.amount.unwrap_or(0),
            reason: e.reason.clone().unwrap_or_else(|| "unknown".into()),
            balance: e.balance,
            uid: e.uid,
        })
        .collect();

    let mut consumed = vec![false; item_adds.len()];
    let mut rows: Vec<SummaryRow> = Vec::new();

    for p in &prop_changes {
        // Pair with a matching item-add for a richer reason label.
        let mut reason = p.reason.clone();
        for (i, it) in item_adds.iter().enumerate() {
            if !consumed[i] && it.amount == p.amount && (it.ts_ms - p.ts_ms).abs() <= 5_000 {
                consumed[i] = true;
                reason = it.reason.clone();
                break;
            }
        }
        rows.push(SummaryRow {
            ts_ms: p.ts_ms,
            time: short_time_ms(p.ts_ms),
            amount: p.amount,
            reason,
            source: "prop",
            balance: p.balance,
            uid: p.uid,
        });
    }

    for (i, it) in item_adds.iter().enumerate() {
        if consumed[i] {
            continue;
        }
        rows.push(SummaryRow {
            ts_ms: it.ts_ms,
            time: short_time_ms(it.ts_ms),
            amount: it.amount,
            reason: it.reason.clone(),
            source: "item",
            balance: it.balance,
            uid: it.uid,
        });
    }

    // "balance" events with amounts but no matching prop/item rows
    // (safety net so nothing is silently lost).
    for e in events.iter().filter(|e| e.kind == "balance") {
        let Some(amount) = e.amount.filter(|a| *a != 0) else { continue };
        let ts_ms = ts_to_ms(&e.ts);
        let matched = prop_changes
            .iter()
            .any(|p| p.amount == amount && (p.ts_ms - ts_ms).abs() <= 5_000)
            || rows
                .iter()
                .any(|r| r.source == "item" && r.amount == amount && (r.ts_ms - ts_ms).abs() <= 5_000);
        if matched {
            continue;
        }
        rows.push(SummaryRow {
            ts_ms,
            time: short_time(&e.ts),
            amount,
            reason: "balance sync".into(),
            source: "sync",
            balance: e.balance,
            uid: e.uid,
        });
    }

    rows.sort_by_key(|r| r.ts_ms);
    rows
}

fn short_time(ts: &str) -> String {
    ts.split_once('T')
        .map(|(_, rest)| rest[..8.min(rest.len())].to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn short_time_ms(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.with_timezone(&Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Aggregate + print a summary; returns rows in print order.
pub fn print_summary(rows: &[SummaryRow], title: &str) {
    println!("=== Mora ledger — {title} ===");
    println!("{:<10} {:>10}  {}", "time", "amount", "action");
    for row in rows {
        println!("{:<10} {:>10}  {}", row.time, row.amount, row.reason);
    }

    let earned: i64 = rows.iter().filter(|r| r.amount > 0).map(|r| r.amount).sum();
    let spent: i64 = rows.iter().filter(|r| r.amount < 0).map(|r| -r.amount).sum();
    println!();
    println!("Events: {}", rows.len());
    println!("Earned: +{earned} Mora");
    println!("Spent:  -{spent} Mora");
    println!("Net:    {:+} Mora", earned - spent);

    if !rows.is_empty() {
        println!();
        println!("By action:");
        let mut by_reason: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
        for row in rows {
            let entry = by_reason.entry(row.reason.clone()).or_default();
            if row.amount >= 0 {
                entry.0 += row.amount;
            } else {
                entry.1 += -row.amount;
            }
        }
        for (reason, (earned, spent)) in by_reason {
            if spent == 0 {
                println!("  {reason}: +{earned}");
            } else if earned == 0 {
                println!("  {reason}: -{spent}");
            } else {
                println!("  {reason}: +{earned} / -{spent}");
            }
        }
    }
}

/// Write rows to a CSV file (spreadsheet friendly).
pub fn write_csv(rows: &[SummaryRow], path: &Path) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "timestamp,time,uid,action,amount,balance_after,source")?;
    for row in rows {
        let ts = ms_to_rfc3339(row.ts_ms);
        writeln!(
            file,
            "{},{},{},{},{},{},{}",
            ts,
            row.time,
            row.uid.map(|u| u.to_string()).unwrap_or_default(),
            csv_escape(&row.reason),
            row.amount,
            row.balance.map(|b| b.to_string()).unwrap_or_default(),
            row.source,
        )?;
    }
    println!("Wrote {} rows to {}", rows.len(), path.display());
    Ok(())
}

/// Copy rows as TSV to the clipboard (paste straight into Google Sheets).
pub fn copy_clipboard(rows: &[SummaryRow]) -> Result<()> {
    let mut text = String::from("timestamp\tuid\taction\tamount\tbalance_after\tsource\n");
    for row in rows {
        let ts = ms_to_rfc3339(row.ts_ms);
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            ts,
            row.uid.map(|u| u.to_string()).unwrap_or_default(),
            row.reason,
            row.amount,
            row.balance.map(|b| b.to_string()).unwrap_or_default(),
            row.source,
        ));
    }
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(text)?;
    println!("Copied {} rows to the clipboard.", rows.len());
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
