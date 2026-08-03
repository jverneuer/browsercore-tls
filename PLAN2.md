# @browsercore/tls — Detailed Status & Implementation Plan

**Authored 2026-08-03.** Supersedes the original `PLAN.md`, whose step statuses were stale
(it marked several completed subsystems as "NOT STARTED").

This document is written for an engineer who will continue the work. It is organized as:

- **Part A — Verified current state** (what is built, where, and how well).
- **Part B — Known defects & dead code** (small, concrete fixes to make first).
- **Part C — The excluded features** (everything the original `PLAN.md` never scoped: post-handshake messages, PSK resumption, 0-RTT, mutual TLS, HelloRetryRequest, certificate compression, stricter validation, TLS 1.2). Each gets an RFC-grounded spec: wire layout, types, functions, crypto-backend deps, integration points, error mapping, tests, effort.
- **Part D — Test strategy & vectors.**
- **Part E — Prioritized roadmap.**
- **Part F — Updated definition of done.**

> **Note on file references.** The `src/handshake/` directory was restructured during this review
> (a single large `handshake.ts` was split into `client-hello.ts`, `server-hello.ts`,
> `state-machine.ts`, and a thin `handshake.ts` barrel). References below are by **module
> responsibility**, not line number, so they survive further internal refactors.

---

## Part A — Verified current state

The package builds clean (`tsc --noEmit` passes) and **159 tests pass / 1 todo**. No
`node:crypto` import exists outside comments. The core TLS 1.3 client handshake is
end-to-end functional.

### A1. Record layer — `src/record/record.ts`

| Symbol | Status |
|---|---|
| `ContentType` (CHANGE_CIPHER_SPEC/ALERT/HANDSHAKE/APPLICATION_DATA) | ✅ |
| `parseRecordHeader` / `serializeRecordHeader` | ✅ validates type, version, length; rejects truncation with `TlsDecryptError` |
| `encryptRecord` / `decryptRecord` | ✅ pure AEAD step, delegates to `@browsercore/crypto`; `decryptRecord` wraps backend `DecryptError` → `TlsDecryptError` |
| `cipherSuiteToAead` | ⚠️ see **B1** — maps `TLS_AES_128_CCM_SHA256` to `"AES-128-GCM"` (wrong) |
| `RECORD_HEADER_SIZE`, `MAX_PLAINTEXT_FRAGMENT` | ✅ |

The TLS 1.3 inner-content-type wrapping (append type byte, strip trailing zeros) is handled
by the caller in `src/connection/record-layer.ts` (`writeEncryptedRecord`/`readEncryptedRecord`),
not in the AEAD primitives — this split is correct per the module's documented responsibility.

### A2. ClientHello — `src/handshake/client-hello.ts` (+ encoders historically in `handshake.ts`)

`buildClientHello(config, keyPairs)` serializes the full handshake message with:
`legacy_version=0x0303`, 32-byte `random` (from `crypto.randomBytes`), empty `session_id`,
`cipher_suites`, `compression_methods=[0x00]`, and an extensions block built from working
private encoders (`encodeServerNameList`, `encodeSupportedVersionsClient`, `encodeKeyShareClient`,
`encodeSignatureAlgorithms`, `encodeAlpn`). All five encoders are **implemented and tested**.

> ⚠️ There are *parallel* `NotImplementedError`-throwing stubs in `src/extensions/extensions.ts`
> (`buildServerNameList`, `buildSupportedVersions`, `buildKeyShare`, `buildSignatureAlgorithms`,
> `buildAlpn`) — see **B2**.

### A3. ServerHello — `src/handshake/server-hello.ts`

`parseServerHello(buf, offered)` parses the body and validates:
- compression method must be `0x00`;
- selected cipher suite was offered (`assertCipherSuiteOffered`);
- `supported_versions` extension present, 2 bytes, and the selected version was both offered
  (`selectVersion`) and supported (`assertVersionSupported`).

Returns `{ protocolVersion, random, sessionId, cipherSuite, compressionMethod, selectedVersion,
extensions }`. Throws `TlsHandshakeError("server_hello")` on any failure.

### A4. Handshake state machine — `src/handshake/state-machine.ts`

Phases: `start → client_hello_sent → server_hello_received → encrypted_extensions_received
→ certificate_received → certificate_verify_received → finished_received → complete`.
`advanceHandshake(current, received)` enforces ordering and throws a *phase-tagged*
`TlsHandshakeError` on any invalid transition. `recordServerHello` attaches the parsed
ServerHello. `completeHandshake` exists but the success path transitions to `open` directly.

### A5. Key schedule — `src/crypto/keySchedule.ts`

Implements RFC 8446 §7.1 locally on top of `@browsercore/crypto`'s HMAC (because the crypto
provider only exposes a combined extract+expand `hkdf`). Present and tested:

- `hkdfExtract` (HMAC-based), `hkdfExpand` (T-block chain), `hkdfExpandLabel` (TLS `tls13 ` label).
- `deriveHandshakeTrafficSecrets` → `{ masterSecret, clientTrafficSecret, serverTrafficSecret }`.
- `deriveHandshakeSecrets`, `deriveApplicationSecrets`, `deriveTrafficSecrets`.
- `updateTrafficSecrets` — **present but unwired** (see **C2**).
- Helpers: `hashFor`, `cipherSuiteToHash`, `cipherSuiteKeyLength`, `cipherSuiteIvLength`,
  `hashLengthFor`, `assertCipherSuiteOffered`, `assertVersionSupported`.

### A6. Certificates — `src/certificates/`

| File | Responsibility | Status |
|---|---|---|
| `der.ts` | TLV, OID, time, AlgorithmIdentifier parsing; `oidToSignatureScheme` | ✅ |
| `cert-extensions.ts` | `parseName`, `parseCommonName`, `parseExtensionsBlock`, `parseSubjectAltNames` (dNSName [2]), `parseKeyUsage` (digitalSignature/keyEncipherment), `parseBasicConstraints` (cA) | ✅ |
| `hostname.ts` | `validateHostname` (RFC 6125, SAN-first, wildcard single leftmost label, CN fallback), `matchDnsName` | ✅ |
| `pem.ts` | `pemToDer` | ✅ |
| `certificates.ts` | `parseCertificate` (captures exact TBS span), `verifyChain` (validity, basicConstraints, signature delegation via `crypto.verifySignature`, trust-anchor SPKI match, hostname) | ✅ |

`verifyChain` is full and correct for the offered signature schemes. Hostname validation is
**fully implemented** (SAN DNS names with wildcard support).

### A7. Extensions — `src/extensions/extensions.ts`

Parsing side is solid: `parseExtensions`, `findExtension`, `wireToExtensionType`,
`signatureSchemeToWire`, `namedGroupToWire`, `wireToNamedGroup`, plus the `ExtensionType`
constant (14 types). **Build side is stubbed** — see **B2**.

### A8. Connection wiring — `src/tls.ts` + `src/connection/*`

- `tls.ts`: `connectTls`, `generateKeyShares` (X25519 only), `TlsConnectionImpl`
  (`handshake`/`read`/`write`/`close`/`on`, 9-step `performHandshake`, `consumeServerFlight`).
- `connection/record-layer.ts`: `xorNonce`, `ensureBytes`, `readHeaderBytes`, `readRawRecord`,
  `readEncryptedRecord`, `writeRecord`, `writeEncryptedRecord`, `concat`.
- `connection/key-exchange.ts`: `computeSharedSecret` (X25519; rejects other groups),
  `transcriptHash`, `verifyServerFinished`.
- `connection/handshake-messages.ts`: `parseAlpnFromEncryptedExtensions`,
  `parseCertificateMessage`, `validateCertificateChain`, `buildClientFinishedMessage`,
  `readEncryptedHandshakeMessage`.
- `connection/lifecycle.ts`: `withTimeout`, `handleAlert`, `ensureOpen`, `emitError`,
  `notifyClose`. (Also contains an unused `handlePostHandshakeRecord` duplicate.)

### A9. Errors — `src/errors.ts`

`TlsError`, `TlsHandshakeError(phase)`, `TlsDecryptError`, `TlsAlertError(level, description)`,
`NotImplementedError`, `TlsPemError`, `TlsKeyScheduleError`, `TlsProfileError`,
`ensureTlsError`. All failures map to a typed error — the error layer is complete.

### A10. Profiles — `src/profiles/profiles.ts`

`resolveProfile`, `getProfile`, `MODERN_TLS13_PROFILE`, `COMPATIBILITY_PROFILE`. Note the
**compatibility profile advertises TLS 1.2+1.3 but the client cannot negotiate 1.2**
(see **C8**); this is a documentation mismatch, not a runtime bug.

---

## Part B — Known defects & dead code (do these first)

These are small, isolated, and should be resolved before adding features.

### B1. `TLS_AES_128_CCM_SHA256` is silently broken (correctness bug)

**Where:** `cipherSuiteToAead` in `src/record/record.ts`.

```ts
case "TLS_AES_128_GCM_SHA256":
case "TLS_AES_128_CCM_SHA256":     // ← falls through
    return "AES-128-GCM";           // ← WRONG for CCM
```

If a server negotiates `TLS_AES_128_CCM_SHA256`, the client will AES-GCM-encrypt/decrypt
with a 16-byte tag. The server expects AES-CCM. **The handshake completes but every record
then fails to decrypt** → opaque `TlsDecryptError`. There is no test covering this suite.

**Also:** `"AES-128-CCM"` / `"AES-128-CCM-8"` are absent from the `AeadAlgorithm` union
(`src/types.ts`), and from the `encryptRecord`/`decryptRecord` switches (an actual CCM value
would hit `assertNever`).

**Fix options:**
- **(a) Drop it.** Remove `TLS_AES_128_CCM_SHA256` from the `CipherSuite` union and from the
  profiles so it is never offered. Simplest; CCM is rare on the public web. Add a test that
  a ServerHello selecting it is rejected.
- **(b) Implement it.** Add `"AES-128-CCM"` (+ optionally `"AES-128-CCM-8"`, 8-byte tag,
  `TLS_AES_128_CCM_8_SHA256`) to `AeadAlgorithm`; require `@browsercore/crypto` to expose
  `aes128CcmEncrypt/Decrypt`; add the switch arms; add round-trip + tamper tests.

**Recommendation:** **(a)** unless a known target requires CCM. Effort: (a) ~1h, (b) ~1–2 days
(assuming the crypto backend gains CCM).

### B2. Dead `NotImplementedError` stubs in `extensions.ts`

`buildServerNameList`, `buildSupportedVersions`, `buildKeyShare`, `buildSignatureAlgorithms`,
`buildAlpn` are exported and **unconditionally throw `NotImplementedError`**. The real encoders
are private functions in the handshake module (`encodeServerNameList`, …). The stubs are never
called (the handshake path uses the private encoders), so they are pure dead weight that
misleads readers and pollutes the public surface.

**Fix:** either (a) delete the five stubs and their `PLAN:` comments, or (b) replace each
private `encode*` in the handshake module with a call to a real `build*` in `extensions.ts`
(so extension building lives with extension parsing, as the file header claims). (b) is the
better long-term factoring. Effort: (a) ~30 min, (b) ~2 h.

### B3. Duplicate `handlePostHandshakeRecord`

The function exists in both `src/tls.ts` (as a private method) and `src/connection/lifecycle.ts`
(as an exported function). The lifecycle copy is never imported. Delete the lifecycle copy, or
make `tls.ts` delegate to it. Effort: ~15 min.

### B4. README/PLAN claim "1.2 fallback" that does not exist

`README.md` says "TLS 1.3 (and 1.2 fallback)" and the original `PLAN.md` step 9 was "NOT STARTED".
The code now *intentionally rejects* TLS 1.2-only profiles (`tls.ts`). Either implement 1.2
(see **C8**) or correct the README/profile naming. Effort: ~15 min if choosing "TLS 1.3 only".

### B5. `COMPATIBILITY_PROFILE` semantics

It advertises `supportedVersions: [TLS_1_3, TLS_1_2]` but cannot honor a 1.2 selection. Rename
to reflect reality (e.g. `BROAD_TLS13_PROFILE` with TLS 1.3 only + conservative suites/groups),
or keep the name and document the limitation. Effort: ~30 min.

---

## Part C — The excluded features (detailed specs)

These were **not scoped** by the original `PLAN.md`. Each subsection is implementation-ready.

---

### C1. HelloRetryRequest + Cookie (RFC 8446 §4.1.3, §4.2.2)

**Problem.** A server may reject the client's first `ClientHello` (e.g. the offered `key_share`
group is unwanted, or it wants to push a `cookie`) by replying with a **HelloRetryRequest** —
which on the wire is a `ServerHello` whose `random` equals the magic value
`CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C`.
The client must then rebuild and resend the `ClientHello`, incorporating any `cookie` extension
and a fresh `key_share` for the group the server requested. **Today the client treats HRR as a
normal ServerHello and will derive garbage keys / fail opaquely.**

**Detection.** In `parseServerHello`, after reading `random`, compare against the HRR magic
constant. If equal, branch to an HRR path instead of the normal handshake.

**Types to add** (`src/handshake/handshake-types.ts` or `state-machine.ts`):
```ts
export const HELLO_RETRY_REQUEST_RANDOM = new Uint8Array([
    0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11, 0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
    0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e, 0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c,
]);
export function isHelloRetryRequest(random: Uint8Array): boolean;
export interface HelloRetryRequest {
    readonly selectedVersion: ProtocolVersion;
    readonly cipherSuite: CipherSuite;
    readonly cookie?: Uint8Array;            // from the cookie extension
    readonly selectedGroup: NamedGroup;      // from the key_share extension
}
```

**Functions to add** (`src/handshake/server-hello.ts`):
```ts
export function parseHelloRetryRequest(buf: Uint8Array, offered: ServerHelloValidation): HelloRetryRequest;
// extracts cookie (type 44) and the single KeyShareEntry group from key_share (type 51).
```

**Key-schedule subtlety (critical).** When HRR occurs, the transcript that feeds the key
schedule is **not** `ClientHello1..ServerHello2`. It is a synthetic transcript:
`Hash(ClientHello1)`, wrapped in a `MessageHash` handshake message (`type 254`), followed by
`HelloRetryRequest`, then `ClientHello2`, then the real `ServerHello`. Concretely
(RFC 8446 §4.4.1):
```
Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    Hash(MessageHash || 00 00 Hash.length || ClientHello1 || HelloRetryRequest || ... Mn)
```
Add a `buildSyntheticTranscript(clientHello1Bytes, hash)` helper and teach `transcriptHash`
/ `TlsConnectionImpl.transcript` to use it when HRR happened.

**Integration in `performHandshake` (tls.ts):**
1. After `parseServerHello`, if `isHelloRetryRequest(random)`: parse as HRR.
2. Reject HRR if already seen one (a server must not send two — `illegal_parameter` alert).
3. Regenerate key shares for `hrr.selectedGroup` (currently only `x25519` is supported by the
   crypto backend — see **C9**; if the server picks a group we can't generate, fail with
   `TlsHandshakeError("server_hello")`).
4. Rebuild `ClientHello2` carrying the `cookie` extension **and** the regenerated `key_share`.
   The rebuilt hello must reuse `ClientHello1`'s `random` and `session_id` and **remove** any
   extensions the server did not echo beyond cookie/key_share (per §4.1.2). Append
   `MessageHash||ClientHello1` then the HRR message to the transcript before pushing ClientHello2.
5. Re-read the *real* ServerHello and continue normally.

**Error mapping:** HRR with no `key_share` → `illegal_parameter`; second HRR → `unexpected_message`.

**Tests:**
- `isHelloRetryRequest` magic match.
- Round-trip: feed a recorded HRR + second ServerHello; assert correct `selectedGroup`,
  echoed `cookie`, and that the final `masterSecret`/application keys match a vector.
- Reject HRR-without-key_share; reject double HRR.
- Verify the synthetic transcript hash against RFC 8446 Appendix or an OpenSSL capture.

**Crypto-backend deps:** none new (still X25519 + SHA-256/384).

**Effort:** ~3–4 days (the transcript synth is the fiddly part).

---

### C2. KeyUpdate (RFC 8446 §4.6.3) — post-handshake

**Current state.** `updateTrafficSecrets(secret, cipherSuite)` exists in `keySchedule.ts` and is
correct. There is no sender, no receiver, and `KEY_UPDATE` (type 24) is silently dropped in
`handlePostHandshakeRecord`.

**Wire layout:**
```
struct {
    KeyUpdateRequest update_requested;   // 1 byte: 0 = update_not_requested, 1 = update_requested
} KeyUpdate;
```
On receipt of `KeyUpdate(update_requested)`:
- receiver immediately updates its **read** keys via `updateTrafficSecrets`,
- and **if `update_requested == 1`**, sends its own `KeyUpdate(update_not_requested)` and
  updates its **write** keys. Sequence numbers reset to 0 on the updated direction.

**Types:**
```ts
export type KeyUpdateRequest = "update_not_requested" | "update_requested";
export function serializeKeyUpdate(req: KeyUpdateRequest): Uint8Array; // [0x18??, 0/1]
export function parseKeyUpdate(body: Uint8Array): KeyUpdateRequest;
```

**Integration:**
- Add `private clientTrafficSecretBase: Uint8Array` and `serverTrafficSecretBase` fields on
  `TlsConnectionImpl` (the raw `c ap traffic` / `s ap traffic` secrets, retained so
  `updateTrafficSecrets` can chain). Currently only the derived `ApplicationTrafficSecrets`
  (key+iv) are kept — the base secret is discarded after `deriveApplicationSecrets`, which
  blocks key updates. **Refactor:** keep the base secrets.
- New method `public async keyUpdate(request: KeyUpdateRequest = "update_requested"): Promise<void>`:
  build `KEY_UPDATE`, encrypt+write under current client traffic key+seq, then immediately
  derive new client write keys (`updateTrafficSecrets`) and reset `clientAppSeq = 0`.
- New handler in the read path: when `readEncryptedRecord` yields an inner `HANDSHAKE` whose
  first body byte is `KEY_UPDATE(24)`, parse it, derive new **server read** keys, reset
  `serverAppSeq = 0`, and if `update_requested`, call `keyUpdate("update_not_requested")`.

**Subtlety:** the key update takes effect on the *next* record in that direction, not the
current one. Sequence numbers must reset to 0 *after* the record carrying the KeyUpdate is
sent/received.

**Tests:**
- `serializeKeyUpdate`/`parseKeyUpdate` round-trip.
- Two endpoints: A sends `keyUpdate`, B updates read key, A updates write key, then app data
  still decrypts.
- Tamper: record encrypted with the *old* key after an update must fail with `TlsDecryptError`.

**Crypto-backend deps:** none new.

**Effort:** ~2–3 days (mostly the base-secret retention refactor + careful seq resetting).

---

### C3. NewSessionTicket + PSK resumption (RFC 8446 §4.6.1, §2.2)

**Current state.** `NEW_SESSION_TICKET` (type 4) is silently ignored. There is no PSK offer,
no binder, no ticket store.

**Wire layouts.**
```
struct {
    uint32 ticket_lifetime;          // seconds, ≤ 604800 (7 days)
    uint32 ticket_age_add;
    opaque ticket_nonce<0..255>;
    opaque ticket<1..2^16-1>;
    Extension extensions<0..2^16-2>; // typically early_data
} NewSessionTicket;
```
PSK binder: `HMAC(finished_key, Transcript-Hash(ClientHello1..truncated at binders))` where
`finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)` and
`binder_key = HKDF-Expand-Label(early_secret, "res binder", "", Hash.length)` (resumption binder
label — distinct from the external "ext binder").

**Components to build:**
1. **Ticket store** (new module `src/session/ticket-store.ts`): in-memory LRU keyed by SNI,
   holding `{ nonce, ticket, ageAdd, lifetime, resumptionSecret }` plus the negotiated cipher
   suite & ALPN. Methods: `record(nst, resumptionSecret, serverName)`, `get(serverName)`,
   `invalidate`. The `resumption_secret` is derived from the master secret via
   `HKDF-Expand-Label(master_secret, "res master", transcript, Hash.length)` then
   `Derive-Secret(resumption_secret, "resumption", transcript)`.
2. **NST parser** (`src/connection/handshake-messages.ts`):
   `parseNewSessionTicket(body): NewSessionTicket`. Called from the read path when an inner
   `HANDSHAKE` with type 4 arrives; computes `resumption_secret` from the retained master secret
   + the *current* transcript, and stores the ticket.
3. **PSK ClientHello offer**: when a ticket exists for the SNI, ClientHello must
   - send `pre_shared_key` (type 41) **last** (RFC requires it be last),
   - send `psk_key_exchange_modes` (type 45) with `psk_dhe_ke (1)`,
   - include a `key_share` (to enable PSK-DHE),
   - append PSK identities (identity = ticket bytes; obfuscated_ticket_age =
     (ticket_age_ms + ticket_age_add) mod 2^32) and binders.
4. **Binder computation** uses the early secret from the PSK: `early_secret = HKDF-Extract(0, psk)`
   (the resumption secret is the PSK). The transcript for the binder is truncated just before
   the binders list itself.
5. **Resumption handshake driver**: after ServerHello, if the server selected PSK (its
   `pre_shared_key` extension echoes our identity index), the handshake secret is
   `HKDF-Extract(derived, DhShared || 0^N)` blended via the early secret branch of the key
   schedule (§7.1 adds a `Derive-Secret(handshake_secret, "c hs traffic"|"s hs traffic", ...)`
   over a transcript that starts from ClientHello1). Reuse the existing
   `deriveHandshakeTrafficSecrets` — it already does `early_secret = HKDF-Extract(0,0)`; the PSK
   path swaps in `HKDF-Extract(0, psk)`.

**Public API:**
```ts
connectTls({ ..., sessionCache?: TlsSessionCache });   // offer tickets if present
const tls = await connectTls(...);
tls.session();  // or an event 'session' carrying the new ticket
```

**Security constraints:**
- Only offer PSK over a fresh DHE (`psk_dhe_ke`); never PSK-only (forward secrecy loss).
- Validate `ticket_lifetime ≤ 7 days`; ignore otherwise.
- PSK cipher suite must equal the original session's.
- Do not resume across different SNI.

**Tests:** binder vector from RFC 8446 (if public), round-trip resume against a Node `tls`
server with `tls.createSecureContext` + session reuse, age-add obfuscation math, reject
expired ticket.

**Effort:** ~1.5–2 weeks (the binder + transcript truncation + early-secret branch are the hard parts).

---

### C4. 0-RTT / early data (RFC 8446 §2.3, §4.2.10, §4.6.1)

**Depends on C3.** After a PSK ticket is accepted, the server may permit `early_data`, letting
the client send application data in its first flight.

**Wire/build:**
- ClientHello includes `early_data` extension (type 42) when offering PSK.
- Server's `EncryptedExtensions` includes `early_data` with `max_early_data_size` to permit it.
- Early data is encrypted under `client_early_traffic_secret =
  Derive-Secret(early_secret, "c e traffic", ClientHello)`, which depends only on the PSK
  (no server input) — computable before the ServerHello arrives.
- The client's first `Finished` covers `ClientHello1..early_data`; the transcript for the
  handshake-traffic derivation prepends the early-data record boundaries via the
  `ClientHello1`-style synthetic transcript.

**Replay risk (must be documented):** 0-RTT data is replayable. Disable by default; only enable
for idempotent requests. Reject `early_data` for non-idempotent application ops, or surface a
`replayable: true` flag to higher layers (fetch must refuse 0-RTT for non-safe methods).

**API:**
```ts
connectTls({ ..., enableEarlyData: true, earlyData?: Uint8Array });
tls.earlyDataAccepted(): boolean;
```

**Effort:** ~1 week (on top of C3). Mark optional / lower priority than C1–C3.

---

### C5. Client authentication / mutual TLS (RFC 8446 §4.3.2, §4.4.2, §4.4.3)

**Current state.** `CertificateRequest` (type 13) is not parsed; the client never sends its own
`Certificate` + `CertificateVerify`. Servers that require client certs abort.

**`CertificateRequest` body (TLS 1.3):**
```
opaque certificate_request_context<0..255>;
Extension extensions<4..2^16-1>;   // signature_algorithms (mandatory), others optional
```
Parse it; capture `certificate_request_context` (must be echoed verbatim in the client's
`Certificate` message) and the accepted `signature_algorithms`.

**Client flight (inserted between EncryptedExtensions and server Finished, server-side order
is: EncryptedExtensions → [CertRequest] → Certificate → CertVerify → Finished):**
1. After reading the server's `CertificateRequest`, the client sends, under the client
   handshake traffic key:
   - `Certificate { certificate_request_context, CertificateEntry[] }` — the client's leaf
     + intermediates. `CertificateEntry.extensions` may carry `client_certificate_type` etc.
   - `CertificateVerify { SignatureScheme, Signature<0..2^16-1> }` — a signature over
     `0x20 * 64 || "TLS 1.3, client CertificateVerify" || 0x00 || Transcript-Hash(ClientHello..Certificate)`
     (64 spaces + the domain separator + zero byte + transcript hash).
2. The client's `Certificate`/`CertificateVerify` are appended to the transcript **before** the
   client computes its `Finished`.

**New types/fields:**
```ts
export interface TlsClientIdentity {
    readonly certificateChain: readonly Uint8Array[];  // DER, leaf first
    readonly privateKey: ClientPrivateKey;              // opaque handle
    readonly signatureAlgorithms: readonly SignatureScheme[];
}
// TlsOptions gains: readonly clientIdentity?: TlsClientIdentity;
```

**Crypto-backend deps:** `crypto.signSignature(scheme, privateKey, message)` — verify whether
`@browsercore/crypto` exposes signing (it exposes `verifySignature` already). If not, add a
signing primitive. The `SignatureScheme` union may need `ed25519`/`rsa_pss_rsae_sha512` for
real client certs.

**Integration:** new branch in `consumeServerFlight` — after EncryptedExtensions, peek the next
message; if `CERTIFICATE_REQUEST`, parse it, then build + send client `Certificate` and
`CertificateVerify` (in the *client's* handshake direction), append both to the transcript, then
continue reading the server's `Certificate`/`CertificateVerify`/`Finished`.

**Error mapping:** no acceptable signature scheme → `internal_error`/`handshake_failure`;
missing client identity when required → `TlsHandshakeError("client_hello")` up front.

**Tests:** mTLS round-trip against Node `tls` server with `requestCert: true`; signature over
the transcript matches; refuse to connect without identity when server requires it.

**Effort:** ~4–5 days (signing primitive + transcript ordering).

---

### C6. Certificate compression (RFC 8879)

**Current state.** `compress_certificate` (type 27) is in `ExtensionType` but neither offered
nor honored. Large chains waste bandwidth; some servers only send compressed chains when the
client offers `compress_certificate`.

**Build:**
- ClientHello `compress_certificate` extension: `AlgorithmList<2..2^8-2>` of supported
  algorithms: `brotli (2)`, `zlib (1)`. (No "zstd" in RFC 8879.)
- On a compressed `CertificateEntry`, the server sets the outer `certificate_list` to a single
  `CertificateEntry` whose `cert_data` is `compressed_certificate_message`:
  ```
  AlgorithmCertificate { algorithm(1), compressed_data<3..2^24-1> }
  ```
- Client must decompress (brotli/zlib), then parse the normal certificate list.

**Dep choice:** `zlib` via `CompressionStream`/`DecompressionStream` (no new native dep in
Node ≥ 18); `brotli` via `BrotliDecompress`. Neither should touch `node:crypto`, so it stays
within the package boundary (compression ≠ cryptography). Prefer offering **brotli** (better
ratios); fall back to zlib.

**Tests:** build a compressed Certificate message, assert decompressed chain matches; reject
unknown algorithm with `bad_certificate`.

**Effort:** ~2 days.

---

### C7. Stricter certificate validation

**Current state.** Validity window, basicConstraints CA, signature, trust-anchor SPKI, and
hostname are checked. Missing:

1. **Extended Key Usage (EKU)** — `parseExtendedKeyUsage` does **not exist** (no stub; just
   absent). For a server leaf, require `id-kp-serverAuth (1.3.6.1.5.5.7.3.1)` (or no EKU at all,
   which some CAs omit). Parse the `extKeyUsage` extension (OID `2.5.29.37` → SEQUENCE OF OID)
   and add an `extendedKeyUsage: readonly string[]` to `Certificate`.
2. **Name constraints** (`2.5.29.30`) on CA certs — enforce permitted/excluded subtrees when
   verifying a chain. Important for private CA hierarchies; rarely needed for the public Web PKI.
3. **Basic constraints `pathLenConstraint`** — currently only the `cA` boolean is read; enforce
   pathLen (no intermediate at depth > pathLen).
4. **Revocation (CRL / OCSP)** — out of scope for an offline client by default, but support
   optional OCSP-stapling (`status_request` ext 5, `CertificateStatus` in `CertificateEntry`).
   Mark optional / low priority.
5. **SAN IP-address matching** — `validateHostname` matches DNS names only (comment says so).
   Add iPAddress SAN ([7]) matching for connect-by-IP (`connect({ host: "1.2.3.4" })`).

**Effort:** EKU ~0.5 day; IP SAN ~0.5 day; name constraints ~1 day; pathLen ~0.5 day; OCSP ~3 days.

---

### C8. TLS 1.2 fallback (RFC 5246) — *optional, large*

**Current state.** Intentionally rejected. Implementing it roughly doubles the protocol surface.
Only pursue if a concrete legacy target requires it.

**Required subsystems (separate code paths from TLS 1.3):**
1. **TLS 1.2 record layer** — CBC mode (MAC-then-encrypt, RFC 5246 §6.2.3.2 + §6.2.3.3) and
   AEAD GCM (RFC 5288). CBC padding-oracle-safe handling (constant-time padding check, or refuse
   CBC entirely).
2. **TLS 1.2 key schedule (PRF, not HKDF)** — `PRF(secret, label, seed) = P_hash`, with
   master-secret derivation `MasterSecret = PRF(pre_master_secret, "master secret",
   ClientHello.random + ServerHello.random)`. Key block expansion via `PRF(master_secret,
   "key expansion", serverRandom + clientRandom)`.
3. **Key exchange messages** — `ClientKeyExchange` (RSA, DHE, ECDHE). ECDHE reuses
   `@browsercore/crypto`'s curve ops; RSA key transport is deprecated (do not implement).
4. **Finished** uses `PRF(master_secret, "client finished"/"server finished", Hash(handshake_messages))`
   with the negotiated PRF hash — *not* the TLS 1.3 HMAC-finished.
5. **Signature schemes** — RSA-PKCS1 and ECDSA in `CertificateVerify` (TLS 1.2 signs the
   handshake messages directly, not the §4.4.3 framed string).
6. **Version negotiation** — `supported_versions` absent; negotiate via `legacy_version`. A
   1.2-only ServerHello has no `supported_versions`; `negotiateVersion` must accept a 1.2
   legacy_version when the profile allows it and route to the 1.2 driver.
7. **ChangeCipherSpec** — send/receive the CCS record and flip keys (1.2 has two CCS flips;
   1.3 middlebox-compat has one).

**Shared plumbing:** the record header framing and `Transport` I/O already abstract away the
version; only the encryption and schedule differ. Keep the typed-error layer (`TlsHandshakeError`
phases) identical so callers can't tell which version ran.

**Cipher suite explosion:** add the TLS 1.2 suite set (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
`0xC02B`, `…_AES_256_GCM_SHA384` `0xC02C`, `…_RSA_WITH_AES_128_GCM_SHA256` `0x009C`, etc.) — a
new `CipherSuite12` union, kept disjoint from `CipherSuite` (1.3) so the two drivers never
share a key type.

**Effort:** ~2–3 weeks. **Recommendation: do not implement** unless required; document the
package as TLS 1.3-only instead (fixes B4/B5).

---

### C9. Additional groups & cipher suites

**Current state.** Only X25519 is reachable: `generateKeyShares` and `computeSharedSecret`
throw for any other `NamedGroup` because `@browsercore/crypto` exposes only X25519 key-gen +
shared-secret. The `NamedGroup` union (`secp256r1`, `secp384r1`, `x25519`, `x448`) and
`wireToNamedGroup` accept all four, so a server can select a group we then can't honor.

**Work items (each gated on the crypto backend):**
- **secp256r1 / secp384r1** (NIST curves, widely deployed): need `crypto` to expose keygen,
  shared-secret, and ECDSA sign/verify for the matching curve. Highest interoperability gain.
- **x448**: optional; rarely required.
- **CCM suites** (see B1).
- **RSA-PSS sha512 / Ed25519** signature schemes for broader `signature_algorithms`.

**Failure handling (do regardless):** if a server selects an unsupported group, the handshake
should fail with a typed `TlsHandshakeError("server_hello")` *before* attempting key derivation.
`computeSharedSecret` already throws — ensure the message is actionable ("group X not supported
by the crypto backend; offer only groups the backend can generate"). Consider pruning the offered
`key_share`/`supported_groups` to what the backend supports at handshake start so HRR is less
likely.

**Effort:** secp256r1 ~3–5 days (if backend ready); x448 ~2 days.

---

## Part D — Test strategy & vectors

**Existing coverage** (9 files, 159 tests): record round-trips, extension parsing, key-schedule
vectors, ClientHello/ServerHello, ASN.1 DER edge cases (38 tests), hostname match/mismatch,
profiles, public-API exports, and a handshake happy path.

**Add for the excluded features:**

| Feature | Vector source |
|---|---|
| CCM (B1) | RFC 8448 / known AES-CCM test vector; tamper detection |
| HelloRetryRequest (C1) | RFC 8448 §3 (full HRR trace); synthetic-transcript hash |
| KeyUpdate (C2) | RFC 8446 §4.6.3 + two-endpoint live round-trip |
| PSK / NST (C3) | RFC 8448 §4 (resumption trace); binder computation |
| 0-RTT (C4) | RFC 8448 §5 |
| mTLS (C5) | Node `tls` server `requestCert:true` |
| Compression (C6) | Hand-crafted brotli/zlib Certificate message |
| EKU / IP-SAN (C7) | Real DER certs with/without EKU; IP SAN leaf |

**Integration harness (worth building once):** a loopback harness that runs the client against
Node's built-in `tls.TLSSocket` (server mode) over an in-memory `@browsercore/transport`. This
exercises the full handshake against a known-good stack and covers features (ALPN, mTLS,
resumption, HRR, compression, 0-RTT) that pure unit tests cannot. The original `PLAN.md` step 8
("full handshake against a test server") was never built — this is the single highest-value
testing investment.

**Property/fuzz additions:** feed random/truncated bytes into `parseRecordHeader`,
`parseServerHello`, `parseCertificateMessage`, `parseExtensions` and assert they only ever throw
typed errors (never crash / never return partial state).

---

## Part E — Prioritized roadmap

**Phase 0 — Hygiene (≈1 day).** B1 (CCM), B2 (extension stubs), B3 (duplicate fn), B4/B5
(docs). Clears latent bugs and dead code before new surface.

**Phase 1 — Interop robustness (≈1 week).** C9 secp256r1 (backend permitting) + the loopback
integration harness + C7 EKU/IP-SAN. This maximizes the set of real servers the client can talk
to and gives a regression net for everything below.

**Phase 2 — Mandatory protocol completeness (≈1.5 weeks).** C1 HelloRetryRequest + C2
KeyUpdate. Both are required for correctness against conformant servers (HRR) and for long-lived
connections (KeyUpdate / connection reuse).

**Phase 3 — Session resumption & performance (≈2–3 weeks).** C3 NewSessionTicket/PSK, then C4
0-RTT (optional, gated on replay-safety in the fetch layer).

**Phase 4 — Advanced / situational.** C5 mTLS, C6 compression, C7 name-constraints/OCSP. Pick
per product need.

**Phase 5 — Only if forced.** C8 TLS 1.2 fallback (large; prefer documenting TLS 1.3-only).

---

## Part F — Updated definition of done

- [x] Record header parse/serialize round-trips; rejects malformed input.
- [x] ClientHello builds and parses back losslessly (incl. all five extensions).
- [x] ServerHello parser validates cipher suite + version.
- [x] X.509 certificates parse; hostname validation follows RFC 6125 (SAN-first, wildcard, CN fallback).
- [x] Chain verification delegates signatures to `@browsercore/crypto`.
- [x] Key schedule matches RFC 8446.
- [x] Handshake state machine reaches `open`/`closed` on every path.
- [x] Record encryption/decryption round-trips; tampering detected.
- [x] ALPN negotiation selects the expected protocol.
- [x] `tsc --build` clean; 160 tests pass; no `node:crypto`.
- [ ] **Loopback integration harness** against Node `tls` server (PLAN step 8, never built).
- [x] **B1** — CCM suite either dropped or correctly implemented.
- [ ] **C1** — HelloRetryRequest handled (synthetic transcript).
- [ ] **C2** — KeyUpdate sent/received; base secrets retained.
- [ ] **C3** — NewSessionTicket parsed; PSK resumption round-trips.
- [ ] **C9** — secp256r1 key exchange (when crypto backend supports it).
- [ ] TLS 1.2 fallback — **decided against** (document as TLS 1.3-only).

**Core implementation: ~90% complete. Protocol-completeness for a general-purpose client:
~70%.** The remaining work is the excluded features in Part C; none of it blocks the existing
happy path, but C1 (HRR) is a real correctness gap against conformant servers.
