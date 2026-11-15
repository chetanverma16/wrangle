# Wrangle wire protocol v2

All binary values are base64url **without padding**. Times are Unix milliseconds unless noted. Vectors for every
derivation below are in `protocol/vectors.json` (written by `go test ./internal/proto -update` in the helper).

## Keys and encryption
- Each pairing has two X25519 key pairs: the phone's (`appPub`) and a **fresh** host pair made by the Mac for that
  phone (`hostPub`). A Mac with two phones has two host pairs. A host key is never reused across pairings.
- `key = HKDF-SHA256(ikm = X25519(myPriv, peerPub), salt = "wrangle/v1", info = "envelope" ‖ appPub ‖ hostPub, L = 32)`
- Envelope: `{"v":1,"n":B64(nonce12),"c":B64(ChaCha20-Poly1305(key, nonce, plaintext, aad))}`. `c` is the ciphertext
  followed by the 16-byte tag.
- AADs:
  - event `"<hostId>|<eventId>"`;
  - usage `"<hostId>|usage"`;
  - decision `"<hostId>|<eventId>|decision"`;
  - SSH request `"<hostId>|ssh|<deviceId>"`;
  - SSH reply `"<hostId>|ssh-reply|<deviceId>"`.
- SAS: `d = SHA-256("wrangle/v1/sas" ‖ appPub ‖ hostPub)`. Take the first 24 bits as four 6-bit numbers, big-endian,
  and map each to `sas-words.txt` (64 words, index 0 = first line). Used only on the typed-code path.
- Commitment: `commit(x) = B64(SHA-256("wrangle/v1/commit" ‖ x))`. `hostKeyCommit = commit(hostPub)`.
- QR MAC: `mac = B64(HMAC-SHA256(k, "wrangle/v1/qr" ‖ appPub ‖ hostPub))`, checked by the Mac in constant time.

## Pairing v2 (the Mac starts it)
The helper makes `hostPub`/`hostPriv`, a claim token `t` (16 random bytes) and a MAC key `k` (16 random bytes).
The relay sees only `tokenHash = B64(SHA-256(t))`. It never sees `k`.

1. Host → `POST /v1/pair/offer {hostName, helperVersion, hostKeyCommit, tokenHash}` → `201 {offerId, code, hostId, hostSecret?, expiresAt}`.
   - No auth creates a new host. With host auth, an already-paired Mac reuses its `hostId` (no `hostSecret` in the
     reply) and its older unresolved offers are deleted.
   - Offers expire after 10 minutes. Every unauthenticated offer counts against the IP limit: the 11th offer from one IP
     (IPv6 /64) within 10 minutes gets `429`.
2. The Mac prints a QR of `wrangle://pair?v=1&r=B64(relay URL)&o=<offerId>&t=B64(t)&k=B64(k)&h=B64(hostPub)&n=B64(host name)`
   (at most 512 characters). Below it is the code `XXX-XXX`: 6 characters of Crockford base32
   `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. The phone uppercases it, drops `-` and spaces, and maps O→0, I→1, L→1.
   The phone refuses a QR whose relay differs from its own.

**QR path (no word check).**
3. Phone → `POST /v1/pair/offer/{offerId}/accept {token: B64(t), appPublicKey, mac, deviceName}` (device auth) →
   `204`. Errors: `404` unknown offer or wrong token; `410` expired; `409 {error:"already_accepted"}` (the first
   valid accept wins). **A `409` also means "check `GET /v1/pair/offer/{offerId}`"**: a retry after a lost response
   can get `409` even though this phone's accept went through.
4. Host → `GET /v1/pair/key` (host auth) → `200 {appPublicKey, deviceId, deviceName, path:"qr", mac}`. Other
   answers: `202 {status:"waiting"}`, `410 {status:"expired"}`, `409 {status:"rejected"|"declined"}`.
   The host verifies `mac`. On a mismatch it aborts and saves nothing.
   - If `path` is `"code"` or `mac` is missing, the host runs the code path's word check, with `[y/N]` defaulting to
     No. Only the Mac user's check stops a relay that strips the MAC.
5. The host asks "Connect “<deviceName>”? [Y/n]".
   - Yes → `POST /v1/pair/host-key {hostPublicKey}` → `204` (`409 {error:"expired"}` once the offer is past its expiry), then `POST /v1/pair/confirm` → `204` (the relay creates
     the link and stores both public keys on it).
   - No → `POST /v1/pair/reject`.
6. Phone polls `GET /v1/pair/offer/{offerId}` and gets one of:
   - `{status:"pending"}`
   - `{status:"keyed", hostPublicKey}`
   - `{status:"linked", hostId, hostName, hostPublicKey}`
   - `{status:"rejected"}`
   - `{status:"expired"}`

   On `linked` the phone checks `hostPublicKey` equals `h` from the QR. On a mismatch it saves nothing and calls
   `decline`; because the offer is already `linked`, that answers `409`, and the phone then removes the link with
   `DELETE /v1/hosts/{hostId}/link`.

**Typed-code path (camera unavailable).**
3. Phone → `POST /v1/pair/offer/accept-code {code, deviceName}` (device auth) → `200 {offerId, hostKeyCommit, hostName}`.
   This **claims** the offer for this device (status `claimed`); it carries no key. Errors: `404` wrong or expired
   code; `409 {error:"already_accepted"}` (already claimed, by this phone or another); `429` after 10 attempts per IP
   (IPv6 /64) per 10 minutes, and after 10 per device. Every attempt counts, right or wrong, against both the IP and
   the device (`codedev:<deviceId>`).
4. Phone, now holding `hostKeyCommit` → `POST /v1/pair/offer/{offerId}/app-key {appPublicKey}` (device auth, the same
   device that claimed) → `204` (status `accepted`). A repeat with the same key is `204` too (a retry after a lost
   answer). Errors: `400` bad key; `404` unknown offer or another device's; `409` not claimed by code, or a different
   key; `410` expired.
5. Host → `GET /v1/pair/key` → `{…, path:"code"}` (no `mac`). While the offer is `claimed` it answers
   `202 {status:"waiting"}`.
6. Host → `POST /v1/pair/host-key`. The relay refuses it (`409`) until an app key is stored, and refuses a key whose
   commitment differs from `hostKeyCommit` (`400`).
   - **Why the order matters.** Both keys are fixed before either is revealed: the Mac committed to `hostPub` in the
     offer, and the phone receives that commitment before it sends `appPub`. A relay that wants matching words has
     to choose the host key it will show the phone before it sees the phone's key, so it gets one guess in 2^24 at
     the SAS.
7. Phone polls `GET /v1/pair/offer/{offerId}` until `keyed`, checks `commit(hostPublicKey) == hostKeyCommit`, and
   shows the 4 words. The Mac shows the same words and asks `[y/N]`.
8. Mac yes → `POST /v1/pair/confirm`. Phone "They don't match" → `POST /v1/pair/offer/{offerId}/decline` (device
   auth).

**Decline** (`POST /v1/pair/offer/{offerId}/decline`, device auth, either path) works only before the Mac confirms
(`claimed`, `accepted` or `keyed`; a declined or rejected offer answers `204` again). It marks the offer `declined`,
so the host's `GET /v1/pair/key` and `confirm` get `409`. It never deletes a link. A `linked` offer answers
`409 {error:"linked"}`: the phone then removes the link with `DELETE /v1/hosts/{hostId}/link`, which also tells the
Mac to drop the phone's SSH key.

## SSH enrolment (right after linking)
- Phone → `POST /v1/hosts/{hostId}/ssh {env}` (device auth, linked).
  - Plaintext: `{"sshPublicKey":"ecdsa-sha2-nistp256 AAAA… wrangle@iPhone","deviceName":"iPhone"}`.
  - AAD: `"<hostId>|ssh|<deviceId>"`.
- Relay → host: `{"t":"ssh-enroll","deviceId":"…","env":Envelope}`. It waits up to 15 s for
  `{"t":"ssh-enrolled","deviceId":"…","env":Envelope}` and returns `200 {env}`.
  Errors: `409 {error:"host_offline"}` when no helper is connected (the phone retries for up to 30 s); `504` on
  timeout; `403` not linked.
- Helper: opens the envelope, then writes
  `restrict,pty <type> <base64> wrangle:<deviceId> <deviceName>` to `~/.ssh/authorized_keys`.
  - Creates `~/.ssh` as 700 and the file as 600 if missing, keeps other lines and the file mode, and replaces any
    existing `wrangle:<deviceId>` line.
  - The key must be `ecdsa-sha2-nistp256` or `ssh-ed25519` with no options. The name is cut to 64 printable
    characters.
- Reply plaintext (AAD `"<hostId>|ssh-reply|<deviceId>"`):
  `{"user":"alex","port":22,"addresses":[{"kind":"lan","host":"Mac.local"},{"kind":"lan","host":"192.168.1.20"},{"kind":"tailscale","host":"100.x.y.z"},{"kind":"tailscale","host":"mac.tailnet.ts.net"}],"hostKeys":["ssh-ed25519 AAAA…"],"tmuxPath":"/opt/homebrew/bin/tmux"}`.
  Host keys come from `/etc/ssh/ssh_host_*_key.pub`. The phone trusts exactly their SHA256 fingerprints (no
  trust-on-first-use prompt).

## Removal
- Phone → `DELETE /v1/hosts/{hostId}/link` → `204`. The relay removes the link and keeps `{t:"unlink", deviceId}`
  queued. It sends the message now, and again on every helper connect, until the helper answers
  `{t:"unlinked", deviceId}`. The helper removes the `wrangle:<deviceId>` line and the device's keys.
- Mac → `wrangle remove-device [name]` → `DELETE /v1/pair/link/{deviceId}` (host auth) → `204`, then the same local
  cleanup. The relay queues the same `unlink` for the helper first, so every way a link goes away reaches the helper.
- Mac → `wrangle remove-device --unknown` removes, locally only, every `wrangle:<id>` line in `authorized_keys` whose
  device isn't in `~/.wrangle/config.json` (left behind when setup replaced the Mac's identity). `wrangle doctor`
  lists such lines.

## Event plaintext (inside each envelope)
```json
{"title":"api-server needs you","body":"Claude wants to run git push origin main","command":"git push origin main",
 "agent":"claude","project":"api-server","cwd":"/Users/dev/code/api-server","pane":"%2","session":"<agent session id>"}
```
- `body` is at most 300 characters (longer text is cut with "…").
- `command` (Bash, and Codex shell commands): commands over 500 characters are never sent for remote approval; the
  agent shows its own prompt instead.
- `detail` (approvals for any other tool): the tool input as compact JSON with sorted keys. Over 500 characters, the
  approval is not sent. For these, `body` is `"<Agent> wants to use <Tool>"`, plus `": <file_path>"` when the input
  has one.
- **The phone must show `command` or `detail` in full** before offering Allow; it never truncates either.

## Host ⇄ relay WebSocket (`GET /v1/hosts/connect`, `Authorization: Bearer <hostId>.<hostSecret>`, `X-Wrangle-Helper: <semver>`)
The helper seals every event and usage snapshot once **per linked phone**, with that phone's key.

Host → relay:
- `{"t":"event","id":"<eventId>","kind":"approval|done|waiting|failed|started|resolved","agent":"claude|codex","thread":"<16 hex>","envs":[{"deviceId":"dev_…","env":Envelope}],"expiresIn":120}`.
  - 1–20 entries. Envelopes for phones that aren't linked are dropped.
  - For `resolved`, `id` is the approval's eventId.
- `{"t":"usage","envs":[{"deviceId":"dev_…","env":Envelope}]}`
- `{"t":"ssh-enrolled","deviceId":"…","env":Envelope}`, `{"t":"unlinked","deviceId":"…"}`

Relay → host:
- `{"t":"ack","id":"<eventId>","pushed":true|false}`, sent once per `event`.
- `{"t":"decision","id":"<eventId>","deviceId":"dev_…","env":Envelope}`: sealed by that phone. The helper opens it
  with the key of exactly the `deviceId` named (never another phone's) and accepts it only if the inner `id` equals the eventId and `decision` is
  `allow|deny|always`.
- `{"t":"ssh-enroll","deviceId":"…","env":Envelope}`, `{"t":"unlink","deviceId":"…"}`

If the helper is older than `MIN_HELPER_VERSION`, the relay answers `426 {"error":"helper_outdated","min":"x.y.z"}`.
The helper pings every 20 s and drops the connection if a pong doesn't come within 8 s; a drop fails its pending
approvals at once. When the last host socket closes, the relay closes every pending approval of that host (a later
decision gets `409 already_decided`) and records `lastSeen`. When an approval stops waiting on its timeout or because
no `ack` came within 10 s, the helper sends `resolved` for it.

## Device HTTP API (`Authorization: Bearer <deviceId>.<deviceSecret>` unless marked)
| Method | Path | Body → Response |
|---|---|---|
| POST | /v1/devices (none) | `{apnsToken?, apnsEnv}` → `201 {deviceId, deviceSecret}`; `429` after 20 per IP (IPv6 /64) per 10 minutes |
| PUT | /v1/devices/apns | `{apnsToken, apnsEnv}` → `204` |
| POST | /v1/devices/entitlement | `{jws}` (StoreKit 2 signed transaction) → `200 {pro:true, until}`; `402 {pro:false}` (invalid, expired, revoked, or not Production/Sandbox; a revoked one also clears this device's Pro); `403 {error:"too_many_devices"}` (one purchase serves at most 5 devices) |
| GET | /v1/me | → `200 {pro, proUntil, month, pushesUsed, freePushes}` (`pushesUsed`: this device's pushes in the current UTC month; Pro pushes aren't counted) |
| POST | /v1/pair/offer/{offerId}/accept | see Pairing v2 |
| POST | /v1/pair/offer/accept-code | `{code, deviceName}` → `200 {offerId, hostKeyCommit, hostName}` (claims; see Pairing v2) |
| POST | /v1/pair/offer/{offerId}/app-key | `{appPublicKey}` → `204` (only after the claim; see Pairing v2) |
| GET | /v1/pair/offer/{offerId} | see Pairing v2 |
| POST | /v1/pair/offer/{offerId}/decline | → `204`; `409 {error:"linked"}` once the Mac has confirmed |
| GET | /v1/hosts | → `200 {hosts:[{hostId, hostName, online, lastSeen}]}` |
| POST | /v1/hosts/{hostId}/ssh | `{env}` → `200 {env}`; `409 host_offline`; `504`; `403` |
| DELETE | /v1/hosts/{hostId}/link | → `204`; `404` |
| POST | /v1/approvals/{eventId} | `{hostId, env}` → `200 {ok:true}`; `404` (unknown, or the approval wasn't addressed to this phone; it stays open for the phones it was); `409 {error:"already_decided"}`; `409 {error:"host_offline"}`; `410`; `403` |
| GET | /v1/inbox?since=ms | → `200 {events:[{id, hostId, kind, agent, thread, env, createdAt}]}` (this phone's envelopes, last 24 h; stored per `(host, event, device)`) |
| GET | /v1/usage | → `200 {usage:[{hostId, env, updatedAt}]}` |

Host HTTP API (`Authorization: Bearer <hostId>.<hostSecret>`): `POST /v1/pair/offer` (auth optional),
`GET /v1/pair/key`, `POST /v1/pair/host-key`, `POST /v1/pair/confirm`, `POST /v1/pair/reject`,
`DELETE /v1/pair/link/{deviceId}`.

## APNs payload (built by the relay, per phone)
```json
{"aps":{"alert":{"title":"Wrangle","body":"New activity"},"mutable-content":1,"thread-id":"<thread>","sound":"default"},
 "w":{"h":"<hostId>","e":"<eventId>","k":"approval","env":Envelope}}
```
- `w.env` is the envelope sealed for **this** phone.
- No `category`. The Notification Service Extension sets it only after it has decrypted the event.
- Header `apns-collapse-id: <eventId>`. If the JSON is over 4096 bytes, `w.env` is left out.
