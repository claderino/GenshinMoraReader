# Draft comment for konkers/irminsul#160 (also relevant to #163)

Copy-paste everything below the line into the GitHub issue.

---

I dug into the 7.1 key failure with packet-level forensics and can pinpoint where it breaks — **it's not the bruteforce window, and not the client clock.**

## What still works on 7.1

- pktmon capture, KCP reassembly, handshake
- dispatch key lookup (version 29945) — the early login commands decrypt fine
- `matches_get_player_token_rsp` still finds and RSA-decrypts a legacy seed (8 bytes, via `private_key_5`)

## The actual change

The 7.1 `GetPlayerTokenRsp` now carries **two** base64-encoded RSA-2048 blobs (both decode to exactly 256 bytes) where previously there was one seed blob:

| field (wire order) | size | decrypts with known keys? |
|---|---|---|
| first blob | 344 chars b64 → 256 bytes | **no** — fails with `private_key_4`, `private_key_5`, PKCS#1v1.5 **and** OAEP-SHA1/OAEP-SHA256 |
| second blob | 344 chars b64 → 256 bytes | yes — `private_key_5`/PKCS#1v1.5 → the familiar 8-byte seed |

The session key appears to be derived from material inside the **first** (undecryptable) blob on servers enrolled in the new path, which is why every seed-based derivation fails no matter the time window. Evidence for the time window not being the issue: the client's `GetPlayerTokenReq` and the `Rsp` both report the same `sent_ms` in their PacketHead, and sweeping ±3000 ms around it (plus a ±14 h / 15-min-step timezone sweep, plus true wall clock, ~384k derivation candidates across MT/combine variants) never produces the magic `45 67 … 89 AB`.

Other observations from the same captures:

- the PacketHead `sent_ms` on this machine is ~+3599 s ahead of true UTC epoch on both client and server side (constant across logins) — worth noting for anyone tuning bruteforce windows, but it is not the cause here
- no plaintext PKCS#1 `RSAPrivateKey` DER structures exist in the current `GenshinImpact.exe` (scanned for the `02 01 00 02 82 01 01` 2048-bit signature across the 423 MB binary) — the new private key is presumably obfuscated or built at runtime, in line with `mhypbase.dll`/`HoYoKProtect.sys`
- the rollout is not uniform: some 7.1 sessions still establish session keys (see #163's working capture) while others never do — consistent with a server-side A/B of the new exchange

## Suggested check to fully confirm

Dump the dispatch-decrypted `GetPlayerTokenReq` as well: if the client now transmits a truly random client seed (instead of a time-derived one), the bruteforce approach is structurally dead even on the legacy path, and the fix will have to come from extracting the new key (key "6") like 4/5 were.

I have raw captures (encrypted session packets + the decrypted token rsp) and can share the field-level parse if useful.
