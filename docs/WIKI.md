# GenshinReader — Project Wiki

Deep-dive documentation for the Mora tracker. For the quick overview see the
[README](../README.md). This wiki explains how everything works, what was
learned about the game's protocol, and how to maintain the tool going forward.

---

## Table of contents

1. [The golden rules](#1-the-golden-rules)
2. [Usage](#2-usage)
3. [Data files & formats](#3-data-files--formats)
4. [Architecture](#4-architecture)
5. [Genshin 7.1 protocol findings](#5-genshin-71-protocol-findings)
6. [The Speedify/VPN fix](#6-the-speedifyvpn-fix)
7. [UID detection & multi-region accounts](#7-uid-detection--multi-region-accounts)
8. [Maintenance guide](#8-maintenance-guide)
9. [Troubleshooting](#9-troubleshooting)
10. [Credits & legal](#10-credits--legal)

---

## 1. The golden rules

Three rules cover ~everything:

1. **Start the tracker before you launch the game.** The session encryption
   key is only exchanged at login; the tool must be watching when it happens.
2. **Always launch the game fresh (cold start).** The *fast relogin* path
   (logout → title screen → login from a running client) uses a different,
   currently-undecryptable key exchange (see [§5](#5-genshin-71-protocol-findings)).
   If the dot stays yellow after a relogin: fully exit and relaunch the game.
3. **One login = one region.** Each game region (Asia/Europe/America/…) has
   its own in-game UID and its own ledger file. Switching regions means
   relaunching the game anyway (see rule 2), which keeps the ledgers separate
   automatically.

---

## 2. Usage

### GUI (default)

Double-click `target\release\genshin-mora-reader.exe` → accept UAC → the
tracker window opens.

```
┌────────────────────────────────────────────────────────────────┐
│ ● tracking   1,234,567 Mora   UID 712345678 ▾   today: +350/−0 │
│ status line / hints                                             │
│ ▸ By action (today)          ← per-reason totals                │
│ ┌────────┬────────┬──────────────┬──────┬─────────┬────┐       │
│ │ time   │ amount │ action       │ uid  │ balance │ src│       │
│ └────────┴────────┴──────────────┴──────┴─────────┴────┘       │
│ 📋 Copy for spreadsheet  💾 Export CSV  ↻ Reload  📂 Open       │
└────────────────────────────────────────────────────────────────┘
```

- **Status dot**: 🟡 waiting for login → 🟢 tracking → 🔴 error
- **Account dropdown** (`▾`): appears once a UID has been identified;
  switch between accounts or view "all accounts". The view auto-follows
  whichever account logs in.
- **Copy for spreadsheet**: TSV incl. a uid column — paste straight into
  Google Sheets. Export filenames include the UID when viewing one account.

### CLI

```
genshin-mora-reader capture            # console live feed
genshin-mora-reader capture --stats    # + capture diagnostics every 15s
genshin-mora-reader summary                     # today, all accounts
genshin-mora-reader summary --uid 712345678     # one account
genshin-mora-reader summary --all --clipboard   # TSV → clipboard
genshin-mora-reader summary --date 2026-10-07 --csv out.csv
```

Common flags: `--jsonl <path>` overrides the default ledger location,
`--no-elevate` skips the UAC self-elevation (capture will fail unless already
admin).

---

## 3. Data files & formats

Everything lives in `%LOCALAPPDATA%\GenshinReader\`:

| File | Purpose |
|---|---|
| `mora.jsonl` | Default ledger (events from sessions where no UID was identified) |
| `mora_<uid>.jsonl` | Per-account ledger, one per in-game UID |
| `mora_<uid>-<timestamp>.csv` | CSV exports |
| `reader.log` | Rolling application + library log (diagnostics, header samples) |
| `keydump/` | Login forensics, written only when key derivation fails |

### Ledger row schema (JSONL, one object per line)

```json
{
  "ts": "2026-10-07T16:56:17.472+03:00",   // RFC3339 local time
  "session": "20261007-165537",            // login session id
  "kind": "item_add",                      // prop_change | item_add | balance | session_start
  "amount": 1260,                          // signed Mora delta
  "balance": 5967377,                      // balance after (when known)
  "reason": "DESTROY_MATERIAL",            // action label
  "reason_raw": 1052,                      // ActionReason enum value
  "uid": 712345678,                        // account (from 7.x: avatar votes)
  "command_id": 652                        // wire command id (scrambled per version)
}
```

Event kinds:

- `prop_change` — server-authoritative balance transition
  (`PlayerPropChangeReasonNotify`-shaped; prop 10016)
- `item_add` — Mora obtained as virtual item 202 with an action reason
  (monster kill = 37, chest = 39, quest reward = 2, … ~250 named reasons in
  `src/reasons.rs`)
- `balance` — balance snapshot (login burst / `PlayerPropNotify`-shaped),
  used for calibration and as a safety net

### Export configuration (`export.json`)

Loaded by both the GUI and the CLI `summary`; edited via the GUI's
⚙ Export settings window.

| Field | Meaning |
|---|---|
| `datetime_format` | Any chrono strftime pattern, or `excel` for raw Excel serial numbers (days since 1899-12-30) |
| `reason_map` | Tracker reason label → custom type string (e.g. `Monster kill → Enemy`); unmapped labels pass through |
| `columns` | Ordered output columns: `timestamp`, `date`, `type`, `action`, `amount`, `remaining` (**= amount**, for sheets whose own formulas subtract expenses), `balance` (post-event balance), `uid`, `description` (**empty**, hand-filled marker), `source` |
| `include_header` | Header row on/off (off for paste-appending into an existing sheet) |

The `summary` command de-duplicates the double-reporting of a single gain
(item-add + prop-change within 5 s, same amount) and keeps the richer
action label.

---

## 4. Architecture

```
pktmon (ETW, Windows Packet Monitor API)          src/capture.rs
  │  UDP 22101/22102 frames, all network components
  ▼
frame normalization                                src/capture.rs
  │  raw-IP → synthetic Ethernet, duplicate suppression (120 ms)
  ▼
auto-artifactarium (vendored + patched)           vendor/auto-artifactarium
  │  KCP reassembly → XOR decrypt → GameCommand { command_id, proto_header, proto_data }
  ▼
value-pattern detection                           src/detect.rs
  │  schema-less protobuf walk → Mora events + UID votes
  ▼
ledger                                             src/ledger.rs
  │  per-UID JSONL, balance tracking, dedupe, exports
  ▼
GUI (egui) / CLI                                   src/gui.rs, src/main.rs
```

### Why value patterns instead of command IDs?

HoYo scrambles command IDs every version and has reshuffled protobuf field
numbers between major versions (verified: the same notify had different field
numbers in 2.x vs 3.x). Nothing in `detect.rs` trusts a command ID; packets
are recognized by content:

- **prop change**: lean message containing varint 10016 (`PROP_PLAYER_SCOIN`)
  + two balance-like numerics (float32 or int, old/cur) + a small reason code
- **item add**: submessages shaped `{1: 202, 2: count}` (ITEM_VIRTUAL_SCOIN)
  + a top-level varint that maps into the `ActionReason` enum
- **balance snapshot**: `PropValue`-shaped `{1: 10016, 2: value}` (possibly
  nested as a protobuf map entry)

This makes the detector survive game updates structurally — only the reason
tables and (rarely) plausibility bounds need touching.

### Key facts baked into the code

| Constant | Value | Source |
|---|---|---|
| Mora player property | `10016` (`PROP_PLAYER_SCOIN`) | verified vs IL2CPP dumps + server impls |
| Mora virtual item | `202` (`ITEM_VIRTUAL_SCOIN`) | community proto enums |
| Primogems / Genesis / Resin / Realm currency | 10015 / 10025 / 10020 / 10042 | same |
| Game UDP ports | 22101, 22102 | — |
| Wire magic | `45 67 … 89 AB` | — |

---

## 5. Genshin 7.1 protocol findings

Findings from this project's packet forensics (2026-10-07), including several
things not documented upstream:

### Login flow & the two key paths

```
cold start ──► handshake ──► GetPlayerTokenRsp (1 RSA blob, legacy path)
                            └─► session key derivable ✔ tracking works

fast relogin ─► handshake ──► GetPlayerTokenRsp (2 RSA blobs, new path)
  (logout→login                ├─ blob A: opens with community key 5 (legacy seed)
   from running                └─ blob B: opens with NOTHING known (new exchange)
   client)                        └─► session key NOT derivable ✘
```

- The relogin-path token response carries **two** base64 RSA-2048 blobs
  (344 chars → 256 bytes each). Blob A decrypts with `private_key_5`
  (PKCS#1 v1.5) to the familiar 8-byte seed. Blob B resists all known keys
  and paddings (PKCS#1v1.5, OAEP-SHA1, OAEP-SHA256).
- ~384k derivation candidates (time windows ±14 h in 15-min steps, MT/combine
  variants) were tested offline against captured relogin ciphertext — none
  match. The relogin session key comes from blob B's material.
- This affects upstream tools identically (see irminsul issues #160/#163).
  Their instructions ("start tool, then launch game") simply never hit the
  relogin path.
- No plaintext PKCS#1 DER keys exist in `GenshinImpact.exe` (scanned for the
  2048-bit signature) — the new private key is obfuscated or runtime-derived.
  Until someone extracts it ("key 6"), relogin sessions are opaque. Capture,
  storage and everything downstream stays ready; the next cold start just
  works.

### 7.x wire headers contain almost nothing

Sampled session command headers are 9 bytes: fields 3 (`seq`) and 6
(`sent_ms`) only. `PacketHead.user_id` (field 11 per the community mapping)
is **never populated** — which is why UID detection uses avatar-scene votes
(see [§7](#7-uid-detection--multi-region-accounts)).

### `sent_ms` runs ~1 h ahead of true UTC

On this setup, both client requests and server responses report `sent_ms`
≈ wall clock + ~3599 s (observed consistently across sessions, once +4074 s).
Unexplained, but harmless: it is constant enough that the stock ±1.5 s
bruteforce window around it still succeeds on cold-start logins.

### Header/body separation matters

Up to 6.x, the community library concatenated `PacketHead || body` when
parsing. Hashblen fixed this upstream in Jan 2026 (commits 878e7a4/7c7fdb4);
the konkers fork never merged those fixes. Parsing headers separately is
required for reliable `sent_ms` extraction — this project ports both fixes
plus the `==`-cut token-parsing fix (1f4ac46) into its vendored copy.

---

## 6. The Speedify/VPN fix

Other tools in this family fail on VPNs for two stacked reasons; both are
handled in `src/capture.rs`:

1. **Physical adapters only carry the VPN's encrypted tunnel.** The plaintext
   game traffic exists only on the VPN's virtual adapter. The Windows Packet
   Monitor observes that adapter, so we still see plaintext frames.
2. **Layer-3 tunnel adapters (Wintun — used by Speedify's "Speedify Tunnel")
   deliver frames as raw IP, not Ethernet.** Upstream feeds frames into an
   Ethernet-only parser and silently drops everything. We detect raw-IP
   frames (version nibble 4/6) and wrap them in a synthetic Ethernet header —
   only ethertype/IP/UDP ports matter downstream, so dummy MACs are fine.

Verified end-to-end with Speedify bonding on Windows 11: login key captured
and full tracking through the VPN. `capture --stats` prints per-component
packet counts and framing stats for quick health checks on any setup.

### pktmon delivery quirks (and the patches for them)

- Each packet arrives **once per capture component** (up to ~5 copies).
  → 120 ms duplicate suppression (hash of the normalized frame).
- Handshake packets therefore also arrive ×5, and the stock library performs
  a full state reset **per copy**, mid-login.
  → vendored patch: handshake resets debounced to 1/s.
- The KCP sniffer adopts one conversation id and drops everything else
  forever — stale packets at relogin poison it.
  → vendored patch: re-adopt the conversation after 8 mismatched segments.

---

## 7. UID detection & multi-region accounts

**One account (login) spans multiple regions; each region has its own
in-game UID.** Getting this wrong merges ledgers — an early version mapped
account-id → UID 1:1 and did exactly that. The current design:

1. The login token's **account id** (ASCII digits in `GetPlayerTokenRsp`) is
   read for status display only — never used for file naming.
2. The in-game UID is discovered from **avatar-scene packets**: every
   `SceneAvatarInfo`-shaped submessage (`{1: uid 9-digit, 2: avatar_id
   10xxxxxx}`) carries its owner's UID. At world entry all your avatars vote;
   3+ votes for the same UID locks it in (~10 s after login).
3. Events **buffer in memory** until the UID is locked, then flush into
   `mora_<uid>.jsonl` — no renames, no cross-region leakage.

If a session ends before the world loads (no avatar data), its events fall
back to the default `mora.jsonl`.

---

## 8. Maintenance guide

### When a game update lands

| Symptom | Likely cause | Where to look |
|---|---|---|
| Dot stays yellow on **cold start** | dispatch key changed | `reader.log`: `didn't find decryption key version=X` → obtain the new initial key, add to `keys/gi.json` (keyed by first two bytes of the key, BE) |
| Green but no Mora events | packet shapes drifted | run with `RUST_LOG=debug`, inspect command bodies; adjust value patterns/plausibility bounds in `src/detect.rs` |
| Reason labels wrong/new | enum extended | regenerate the match arms in `src/reasons.rs` (values sourced from community protos) |
| Yellow after **relogin** | expected — 7.1 relogin path | no action; cold start works |

### Built-in analysis tools (`cargo run --release --bin <name>`)

- **keycrack** — loads the latest `keydump/` failure artifacts and tests
  ~384k seed/key derivations (time windows, MT variants, XOR/ADD combines)
  offline. Extend its hypothesis list when testing new derivation ideas.
- **seedscan** — dissects a dumped token response: finds every
  length-delimited field, base64/RSA-decrypts with keys 4/5 across all
  paddings, reports which field yields the 8-byte seed. Use to check whether
  a new game version changed the blob layout.
- **keyhunt** — scans game binaries for embedded PKCS#1 private keys
  (`02 01 00 02 82 01 01` signature) and tests every candidate against the
  captured undecryptable blob. If HoYo ships a plain key someday, this finds
  it in minutes; save it as `vendor/.../keys/private_key_6.pem` and register
  it in `GameSniffer::new()`.

The tool dumps login forensics to `keydump/` automatically whenever key
derivation fails — new hypotheses can be validated against real captured
bytes without asking anyone to log in again.

### Vendored patches (vs konkers/auto-artifactarium @ abbbf7a)

`vendor/auto-artifactarium` is upstream plus:

1. Handshake reset debouncing (`last_handshake_reset`)
2. KCP conversation re-adoption (`sent/recv_conv_mismatches`, `KcpSniffer::conv()`)
3. Extended timezone key sweep + failure caching (`bruteforce_extended`,
   `failed_key_search`)
4. `==`-cut token parsing and header/body separation (ported from hashblen
   1f4ac46 / 878e7a4)
5. `account_uid()` extraction; forensics dumps (`dump_artifacts`,
   `dump_key_failure`); `recv_command` logging tweaks

If upstream ever lands equivalent fixes, re-evaluate which patches to keep.

### Build

```
cargo build --release        # → target\release\genshin-mora-reader.exe
cargo test                   # unit tests incl. detector patterns
```

Requires the Rust MSVC toolchain. `build.rs` embeds the icon
(`assets/icon.ico`, generated by `assets/pack_icon.ps1` from the official
`UI_ItemIcon_202` asset) and file metadata.

---

## 9. Troubleshooting

| Observation | Meaning / action |
|---|---|
| 🟡 dot, no status change while playing | Tool started after login — relogin won't help if it's the 7.1 fast path; cold start the game |
| "Login detected, but the session key could not be derived" | Relogin path (expected) — fully exit and relaunch the game |
| `[stats]` shows packets but all `skipped` | L4-only framing somewhere — report the stats line |
| `[stats]` shows zero packets | Check admin rights; VPN toggled mid-session can also re-route — restart capture |
| Events land in `mora.jsonl` instead of a UID file | World never loaded / avatar packets missed that session; file manually if needed |
| Two regions merged in one file | Only possible with pre-fix data; rows are split-able by `session` id |

---

## 10. Credits & legal

- **konkers/irminsul** and **juliuskreutz/stardb-exporter** — architecture
  and the capture approach; irminsul is MIT.
- **hashblen/auto-artifactarium** (and konkers' fork) — the decryption core;
  MIT. Vendored with the patches listed in §8.
- **emmachase/pktmon** — ETW capture without Npcap.
- **Sorapointa** — community proto definitions (enums, message shapes).
- Protocol findings in §5–§7 documented from this project's own captures;
  a writeup draft for upstream lives in `upstream-issue-draft.md`.

This is a passive scanner of your own game traffic: no game memory is read,
nothing leaves the machine. Like all third-party game tooling it is still
technically against the Terms of Service — use at your own discretion.
