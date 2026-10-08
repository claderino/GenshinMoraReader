# GenshinReader

Passively reads Genshin Impact's network traffic and records **every Mora gain — and the action that earned it** (monster kills, chests, quests, commissions, domains, expeditions, reputation, ~250 named reasons in total). Also tracks spending and your running balance.

📖 **Full documentation: [docs/WIKI.md](docs/WIKI.md)** — architecture, protocol findings (7.1 key exchange, VPN capture, UID detection), maintenance guide and troubleshooting.

Built on the same proven stack as [irminsul](https://github.com/konkers/irminsul) and [stardb-exporter](https://github.com/juliuskreutz/stardb-exporter):

- **Capture**: Windows built-in `pktmon` (ETW) — *no Npcap/WinPcap install needed*, admin rights required
- **Decrypt**: [auto-artifactarium](https://github.com/konkers/auto-artifactarium) handles KCP reassembly, the login key exchange capture and XOR decryption
- **Detect**: version-proof value-pattern matching (HoYo scrambles command IDs and reshuffles protobuf field numbers between versions, so this tool matches on *content*: property id `10016`, virtual item id `202`, reason enums)

## Usage

**GUI (default)** — double-click `genshin-mora-reader.exe` (or run it with no arguments):

1. Accept the UAC prompt (packet capture needs admin)
2. The tracker window opens: status dot, current Mora balance, today's earned/spent
3. Launch Genshin Impact and log in — the dot turns green ("tracking") once the session key is captured
4. Every Mora change appears live in the table (newest first, color-coded) and is saved to the ledger

Buttons at the bottom:

- **Copy for spreadsheet** — puts today's rows on the clipboard as TSV; paste straight into Google Sheets
- **Export CSV** — writes a timestamped CSV next to the ledger
- **By action (today)** — collapsible per-reason totals
- **Reload history** — re-reads the ledger (e.g. after a previous session)

**CLI** (still available for scripting):

```
genshin-mora-reader capture          # console live feed instead of the GUI
genshin-mora-reader capture --stats  # + capture diagnostics every 15s (VPN checks)
genshin-mora-reader summary          # today's totals in the console
genshin-mora-reader summary --all
genshin-mora-reader summary --date 2026-10-07 --csv out.csv
genshin-mora-reader summary --all --clipboard
```

**Flow:** start the tool (accept the UAC prompt) → launch the game → log in (walk through the door). The session key is only exchanged at login, so the game session must *begin* while the tool runs. From then on every Mora change prints live and is appended to the ledger.

The ledger is a JSONL file at `%LOCALAPPDATA%\GenshinReader\mora.jsonl` (override with `--jsonl`). Each line:

```json
{"ts":"2026-10-07T18:42:11.482+02:00","session":"20261007-184159","kind":"prop_change","amount":1250,"balance":4513450,"reason":"FINISH_QUEST","reason_raw":11,"command_id":1210}
{"ts":"...","kind":"item_add","amount":350,"reason":"Monster kill","reason_raw":37,"command_id":64201}
```

- `kind=prop_change` — server-authoritative balance transition (`PlayerPropChangeReasonNotify`-shaped)
- `kind=item_add` — Mora obtained as item 202 with an `ActionReason` (monsters, chests, quests…)
- `kind=balance` — balance snapshot used for reconciliation

`summary` de-duplicates the item/prop double-reporting of the same gain and prints totals per action.

## How Mora detection works

| Source packet | Marker | Gives us |
|---|---|---|
| `PlayerPropChangeReasonNotify` | prop id `10016` (`PROP_PLAYER_SCOIN`) | old → new balance + `PropChangeReason` |
| `ItemAddNotify` (and reward-style packets) | virtual item `202` (`ITEM_VIRTUAL_SCOIN`) | amount + `ActionReason` (monster kill = 37, chest = 39, quest reward = 2, …) |
| `PlayerPropNotify` / login data | prop map keyed `10016` | exact balance snapshots |

> Note: in prop-change packets the balances travel as `float32`, which is exact only up to 16,777,216 — for larger balances values may round slightly. Item-add counts and balance snapshots are exact integers, and the summary reconciles the three sources.

## Genshin 7.1 status — the relogin caveat

**Working:** launching the game fresh while the reader runs (the normal flow). Cold-start logins use the legacy key exchange and decrypt fine — verified end-to-end (balance snapshots at login + live Mora events with action reasons).

**Not working:** the *fast relogin* path (logging out to the title screen of an already-running client and logging back in). Those sessions use a new key exchange: the token response carries a **second** RSA-2048-encrypted blob (verified from packet dumps) that no known community key can open (PKCS#1v1.5, OAEP-SHA1, OAEP-SHA256 all tried), and ~384k derivation candidates against the captured ciphertext all fail. If the dot stays yellow after a relogin: **fully exit the game and relaunch it** — the reader automatically picks up the next cold-start login.

This affects upstream tools equally (see [irminsul#160](https://github.com/konkers/irminsul/issues/160)); their usual instructions (start tool → launch game) simply never hit the relogin path. The rollout may also be regional/account-dependent — if cold starts ever stop working too, re-check the forensics below.

**Diagnostics & research tooling included:** on key-capture failure the tool dumps the login material to `%LOCALAPPDATA%\GenshinReader\keydump`; `cargo run --bin keycrack` tests derivation hypotheses offline, `seedscan` dissects token responses, and `keyhunt` scans game binaries for candidate private keys against captured blobs — so a future key can be validated instantly without another login.

## Caveats

- Must be running **before login** each session, and the game should be **launched fresh** (see "Genshin 7.1 status" — relogins from a running client use an encrypted key exchange this tool can't currently derive). If you relog mid-session, fully restart the game.
- Passive sniffing of your own game traffic, in the same spirit as inventory scanners (irminsul, stardb-exporter). No game memory is read and nothing is sent anywhere — but third-party tooling is still technically against HoYo's ToS. Use at your own discretion.
- If a future version changes packet shapes enough to evade the value-pattern detectors, run with `RUST_LOG=debug` and check `command_id` diagnostics; the tables in `src/detect.rs` and `src/reasons.rs` are easy to update.

## VPN (Speedify and friends)

Other tools in this family (stardb-exporter's pcap mode, irminsul) are known to fail while a VPN runs. Two separate reasons, both handled here:

1. **Physical adapters only see the VPN's encrypted tunnel.** The plaintext game packets exist only on the VPN's virtual adapter. The Windows Packet Monitor observes that adapter, so we still see the plaintext.
2. **Layer-3 tunnel adapters (Wintun — used by Speedify's "Speedify Tunnel") deliver frames as raw IP, not Ethernet.** Upstream tools parse Ethernet only and silently drop everything. This tool detects raw-IP frames and wraps them in a synthetic Ethernet header before parsing (only ethertype/IP/UDP ports matter downstream).

Verified working with Speedify (bonding mode) on Windows 11: packets arrive from the tunnel components, the login key exchange is captured, and game commands decrypt normally.

If capture ever looks silent while a VPN runs, add `--stats` to see per-component packet counts and framing details, e.g.:

```
genshin-mora-reader capture --stats
```

## Credits

- [konkers/irminsul](https://github.com/konkers/irminsul) & [juliuskreutz/stardb-exporter](https://github.com/juliuskreutz/stardb-exporter) — architecture reference and dispatch keys
- [hashblen/auto-artifactarium](https://github.com/hashblen/auto-artifactarium) (and konkers' fork) — the decryption/parsing core
- [emmachase/pktmon](https://github.com/emmachase/pktmon) — ETW packet capture without Npcap
- [Sorapointa](https://github.com/Sorapointa/Sorapointa) — community proto definitions (`ActionReasonType`, prop ids, message shapes)
