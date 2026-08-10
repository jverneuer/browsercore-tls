# TLS 1.3 Implementation Plan — @browsercore/tls

> **Status:** Read-only architecture audit of `@browsercore/tls@0.4.3`.
> **Goal:** Bring the from-scratch TLS 1.3 client to production quality by
> closing all protocol gaps and resolving the handshake stall against real servers.
> **Scope:** `src/` source + `tests/` test suite. External deps
> (`@browsercore/transport`, `@browsercore/crypto`) are referenced but not modified.

---

## Table of Contents

1. [Gap Matrix](#1-gap-matrix)
2. [Bug Analysis: Handshake Stall Root Cause](#2-bug-analysis-handshake-stall-root-cause)
3. [Architecture Recommendations](#3-architecture-recommendations)
4. [Implementation Phases](#4-implementation-phases)
5. [Critical Files for Implementation](#critical-files-for-implementation)

---

## 1. Gap Matrix

Legend: **✅** Implemented · **🔶** Partial · **🔴** Stubbed · **❌** Missing

### 1.1 Core Handshake Protocol (RFC 8446 §4)

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| ClientHello construction | ✅ | §4.1.2 | `handshake/client-hello.ts` | — | — |
| ServerHello parsing | ✅ | §4.1.3 | `handshake/server-hello.ts` | — | — |
| HelloRetryRequest handling | ❌ | §4.1.3 | — (not in `server-hello.ts`) | **P1** | M |
| Handshake state machine | ✅ | §4.1 | `handshake/state-machine.ts` | — | — |
| EncryptedExtensions parsing | ✅ | §4.3.1 | `connection/handshake-messages.ts` | — | — |
| Certificate message parsing | ✅ | §4.4.2 | `connection/handshake-messages.ts` | — | — |
| **CertificateVerify verification** | **🔴** | §4.4.3 | `connection/handshake-driver.ts:282-285` | **P0** | M |
| Server Finished verification | ✅ | §4.4.4 | `connection/key-exchange.ts:106-126` | — | — |
| Client Finished construction | ✅ | §4.4.4 | `connection/handshake-messages.ts:130-144` | — | — |
| CertificateRequest handling | ❌ | §4.3.2 | — | P3 | M |
| Post-handshake authentication | ❌ | §4.6.2 | — | P4 | L |

**🔴 CertificateVerify — CRITICAL SECURITY VULNERABILITY:**
The CertificateVerify message is pushed to the transcript (`handshake-driver.ts:285`) but
its signature is **never verified** against the server's certificate public key. The server
sim confirms this: it sends a dummy signature (`server-sim.ts:246-248`, 64 bytes of `0xee`)
that the client blindly accepts. Any MITM who controls the certificate bytes can forge a
valid-looking handshake. This is the single most dangerous gap in the codebase.

**❌ HelloRetryRequest:** The server sends HRR (a special ServerHello with the sentinel
random `CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A23721`) when the client's
key share is unacceptable. The code does not detect this sentinel, so an HRR would be
processed as a regular ServerHello, corrupting the transcript and key schedule. This won't
trigger against X25519-only servers but will fail against servers that prefer other groups.

### 1.2 Key Schedule (RFC 8446 §7.1)

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| Early Secret derivation | ✅ | §7.1 | `crypto/keySchedule.ts:270-272` | — | — |
| Handshake Secret derivation | ✅ | §7.1 | `crypto/keySchedule.ts:274-293` | — | — |
| Master Secret derivation | ✅ | §7.1 | `crypto/keySchedule.ts:296-299` | — | — |
| Handshake traffic secrets | ✅ | §7.1 | `crypto/keySchedule.ts:287-288` | — | — |
| Application traffic secrets | ✅ | §7.1 | `crypto/keySchedule.ts:355-360` | — | — |
| HKDF-Expand-Label | ✅ | §7.1 | `crypto/keySchedule.ts:200-226` | — | — |
| Traffic key/IV derivation | ✅ | §7.1 | `crypto/keySchedule.ts:232-243` | — | — |
| KeyUpdate secret derivation | 🔶 | §7.1 | `crypto/keySchedule.ts:367-380` | **P2** | S |
| Resumption Master Secret | ❌ | §7.1 | — | P3 | M |
| Early Data (0-RTT) secret | ❌ | §7.1 | — | P4 | M |
| **Test vectors (known-answer)** | **❌** | §7.1 | — | **P1** | S |

**🔶 KeyUpdate:** `updateTrafficSecrets()` exists in `keySchedule.ts:370-380` but is never
called. `KeyUpdate` messages received from the server are silently dropped
(`lifecycle.ts:42-43`). The function computes the next traffic secret correctly but there is
no wiring to apply it to the connection's traffic keys or reset sequence numbers.

**❌ Test vectors:** The key schedule is tested only for structural properties (output
lengths, determinism) — never against published TLS 1.3 known-answer test vectors. This means
subtle bugs in HKDF-Expand-Label or Derive-Secret computation could go undetected. The
key schedule was confirmed correct per RFC 8446 §7.1 (verified: the `0` value in
`HKDF-Extract(0, PSK)` means a string of `Hash.length` zero bytes, matching the code at
`keySchedule.ts:271`).

### 1.3 Record Layer (RFC 8446 §5)

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| Record header parse/serialize | ✅ | §5.1 | `record/record.ts:136-173` | — | — |
| AEAD encrypt/decrypt | ✅ | §5.2 | `record/record.ts:180-265` | — | — |
| Per-record nonce construction | ✅ | §5.3 | `connection/record-layer.ts:41-57` | — | — |
| Inner content type stripping | ✅ | §5.2 | `connection/record-layer.ts:128-147` | — | — |
| CCS record filtering (handshake) | ✅ | §5 | `connection/handshake-messages.ts:210-230` | — | — |
| CCS record filtering (app data) | ❌ | §5 | `connection/record-layer.ts:109-117` | P3 | S |
| Zero-padding stripping | ✅ | §5.1 | `connection/record-layer.ts:131-133` | — | — |
| Record length validation | 🔶 | §5.1 | `record/record.ts:136-153` | **P2** | S |
| Max fragment length enforcement | ❌ | §5.1 | — | P3 | S |

**🔶 Record length:** `parseRecordHeader` reads the length field but does not validate it
against `MAX_PLAINTEXT_FRAGMENT` (16,384) or the encrypted maximum (16,384 + 256). A
malicious server could send an oversized record that causes excessive memory allocation in
`ensureBytes`. The constant `MAX_PLAINTEXT_FRAGMENT` is defined at `record.ts:36` but never
enforced.

### 1.4 Alert Protocol (RFC 8446 §6)

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| Alert consumption (received) | ✅ | §6 | `connection/lifecycle.ts:56-74` | — | — |
| close_notify sending | ✅ | §6.1 | `tls.ts:346-357` | — | — |
| **Alert sending (protocol errors)** | **❌** | §6 | — | **P2** | M |
| Alert level semantics | 🔶 | §6 | `lifecycle.ts:69-70` | P3 | S |

**❌ Alert sending:** When the client detects an error (bad cipher suite, bad Finished,
cert validation failure), it throws an exception but never sends a TLS alert to the server.
RFC 8446 §6 requires the client to send an appropriate alert before closing the connection.
Currently only `close_notify` (level=warning, description=0) is sent, and only during
graceful close. Missing: `handshake_failure` (40), `bad_certificate` (42), `decrypt_error`
(51), `illegal_parameter` (47), etc.

### 1.5 Certificate Validation

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| DER parsing | ✅ | RFC 5280 | `certificates/der.ts` | — | — |
| X.509 field extraction | ✅ | RFC 5280 | `certificates/certificates.ts` | — | — |
| Hostname validation (SAN/CN) | ✅ | RFC 6125 | `certificates/hostname.ts` | — | — |
| Wildcard matching | ✅ | RFC 6125 §6.4.3 | `certificates/hostname.ts:34-48` | — | — |
| IP address SAN matching | ❌ | RFC 6125 §6.4 | `certificates/hostname.ts` | P3 | S |
| Chain signature verification | ✅ | RFC 5280 | `certificates/certificates.ts:268-351` | — | — |
| Trust anchor matching | ✅ | RFC 5280 | `certificates/certificates.ts:328-334` | — | — |
| Validity period check | ✅ | RFC 5280 | `certificates/certificates.ts:278-284` | — | — |
| **CertificateVerify signature** | **🔴** | RFC 8446 §4.4.3 | — | **P0** | M |
| Path building (multi-intermediate) | 🔶 | RFC 5280 §6 | `certificates/certificates.ts:303-310` | P2 | M |
| OCSP stapling | ❌ | RFC 6066 §8 | — | P3 | M |
| CRL checking | ❌ | RFC 5280 | — | P4 | M |
| Certificate Transparency | ❌ | RFC 6962 | — | P4 | M |
| Name constraints checking | ❌ | RFC 5280 §4.2.1.10 | — | P4 | M |

**🔶 Path building:** `verifyChain` assumes the certificates in the server's Certificate
message are already in the correct order (leaf → intermediate(s) → root). It does not
attempt to build a path from multiple possible ordering or cross-signed intermediates. This
works for most real-world chains but fails for unusual configurations.

**🔴 CertificateVerify signature:** See §1.1 above — the signature in CertificateVerify is
never checked.

### 1.6 Session Management

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| NewSessionTicket consumption | ❌ | §4.6.1 | — | P3 | M |
| Session resumption (PSK) | ❌ | §2.2 | — | P3 | L |
| Session ticket cache | ❌ | §4.6.1 | — | P3 | M |
| 0-RTT early data | ❌ | §2.3 | — | P4 | L |
| PSK key exchange modes | 🔶 | §4.2.9 | `client-hello.ts:330-332` (advertised only) | P4 | M |

### 1.7 Extensions

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| SNI (server_name) | ✅ | §4.2.1 / RFC 6066 §3 | `client-hello.ts:352-367` | — | — |
| supported_versions | ✅ | §4.2.1 | `client-hello.ts:372-385` | — | — |
| key_share (client) | ✅ | §4.2.8 | `client-hello.ts:388-428` | — | — |
| key_share (server parse) | ✅ | §4.2.8 | `connection/key-exchange.ts:21-53` | — | — |
| signature_algorithms | ✅ | §4.2.3 | `client-hello.ts:432-447` | — | — |
| ALPN | ✅ | §4.2.10 / RFC 7301 | `client-hello.ts:451-469` | — | — |
| supported_groups | ✅ | §4.2.7 | `client-hello.ts:276-299` | — | — |
| pre_shared_key | 🔶 | §4.2.11 | `client-hello.ts:254` (empty body) | P4 | M |
| psk_key_exchange_modes | 🔶 | §4.2.9 | `client-hello.ts:330-332` (hardcoded) | P4 | S |
| early_data | ❌ | §4.2.10 | — | P4 | M |
| cookie (HRR) | ❌ | §4.2.2 | — | P2 | S |
| status_request (OCSP) | 🔶 | §4.2.6 / RFC 6066 §8 | `client-hello.ts:334` (empty body) | P3 | M |
| signature_algorithms_cert | ❌ | §4.2.3 | — | P3 | S |
| record_size_limit | ❌ | §4.2.14 / RFC 8449 | — | P3 | S |
| compress_certificate | 🔶 | RFC 8879 | `client-hello.ts:314-327` (advertised, not processed) | P3 | M |
| GREASE | ✅ | RFC 8701 | `handshake/client-hello.ts:34-66` | — | — |

### 1.8 Cipher Suites, Groups, Signature Schemes

| Feature | Status | File(s) | Priority | Effort |
|---------|--------|---------|----------|--------|
| AES-128-GCM | ✅ | `record/record.ts:82` | — | — |
| AES-256-GCM | ✅ | `record/record.ts:83` | — | — |
| ChaCha20-Poly1305 | ✅ | `record/record.ts:84` | — | — |
| AES-128-CCM | ✅ | `record/record.ts:81` (untested live) | P2 | S |
| AES-128-CCM-8 (short tag) | ❌ | — | P4 | S |
| X25519 key exchange | ✅ | `connection/key-exchange.ts:68-69` | — | — |
| secp256r1 key exchange | ✅ | `connection/key-exchange.ts:70-71` | — | — |
| secp384r1 key exchange | ✅ | `connection/key-exchange.ts:70-71` | — | — |
| secp521r1 key exchange | ❌ | `connection/key-exchange.ts:75-79` | P3 | M |
| x448 key exchange | ❌ | `connection/key-exchange.ts:75-79` | P4 | M |
| FFDHE groups | ❌ | `connection/key-exchange.ts:76-79` | P4 | M |
| Post-quantum hybrid (Kyber/MLKEM) | 🔶 | Advertised only (`types.ts:87-88`) | P4 | L |
| ECDSA signature verification | ✅ | `certificates/der.ts:217-219` | — | — |
| RSA-PSS verification | ✅ | `test-helpers.ts:305-316` | — | — |
| RSA-PKCS1 verification | ✅ | `test-helpers.ts:317-319` | — | — |
| Ed25519 verification | ❌ | — | P2 | M |

### 1.9 Security & Protocol Hardening

| Feature | Status | RFC § | File(s) | Priority | Effort |
|---------|--------|-------|---------|----------|--------|
| **Downgrade protection sentinel** | **❌** | §4.1.3 | — | **P1** | S |
| Middlebox compatibility (CCS) | ✅ | §5 | `handshake-messages.ts:210-230` | — | — |
| Constant-time comparison | ✅ | — | `utils.ts:26-44` | — | — |
| Replay protection (0-RTT) | ❌ | §8 | — | P4 | L |
| Exporter keying material | ❌ | §7.5 | — | P3 | S |
| Empty record flood protection | ❌ | §5.1 | — | P3 | S |
| Record version validation | ❌ | §5.1 | `record/record.ts:152` | P3 | S |
| handshake→application key transition | 🔶 | §5.2 | implicit in driver | P2 | S |

**❌ Downgrade protection:** RFC 8446 §4.1.3 requires the client to check the last 8 bytes
of the ServerHello `random` field for the sentinel `44 4F 57 4E 47 52 44 01` (TLS 1.2
downgrade) or `44 4F 57 4E 47 52 44 00` (TLS 1.1 or below). If present in a TLS 1.3
ServerHello, the client MUST abort with `illegal_parameter`. The current code parses
`random` at `server-hello.ts:121` but never checks these sentinels.

### 1.10 Error Handling & Observability

| Feature | Status | File(s) | Priority | Effort |
|---------|--------|---------|----------|--------|
| Typed error hierarchy | ✅ | `errors.ts` | — | — |
| Phase-tagged handshake errors | 🔶 | `errors.ts:30-33` | P2 | S |
| Structured error details | ✅ | `errors.ts:13-17` | — | — |
| Debug tracing/logging | ❌ | — | **P1** | S |
| Timeout attribution | 🔴 | `lifecycle.ts:15-19` | **P1** | S |

**🔴 Timeout attribution:** `withTimeout` at `lifecycle.ts:15-19` hardcodes phase `"finished"`
in the error message regardless of where the stall actually occurs. This makes it impossible
to determine the true stall point from the error alone. The `HandshakePhase` union only
contains four values (`client_hello | server_hello | certificate | finished`), so even if
the phase were tracked correctly, intermediate phases like `encrypted_extensions` or
`certificate_verify` are not representable.

**❌ Debug tracing:** There is no logging or tracing infrastructure. When a handshake stalls,
there are zero diagnostics to determine which step is blocking. This is the primary
obstacle to debugging the stall.

### 1.11 Real-World Production Requirements (non-RFC)

| Feature | Status | Priority | Effort |
|---------|--------|----------|--------|
| Session caching / pool integration | ❌ | P3 | M |
| TLS 1.2 fallback (clean rejection) | ✅ (rejects cleanly) | — | — |
| TLS 1.2 handshake implementation | ❌ (aspirational only) | P4 | XL |
| Connection close on error | 🔶 | P2 | S |
| Graceful degradation (retry) | ❌ | P3 | M |
| Memory safety (malformed input) | ✅ (mostly) | — | — |
| Resource cleanup on timeout | ❌ | P2 | S |

**🔶 Connection close on error:** When a handshake error occurs, the transport is left
open — `close()` is not called. The pending `transport.read()` inside `ensureBytes` never
resolves, potentially leaking the socket.

**❌ TLS 1.2:** The README and code comments reference `runTls12Handshake()` which does not
exist. The code rejects TLS 1.2-only profiles upfront (`handshake-driver.ts:125-129`) and
throws on TLS 1.2 cipher suite negotiation (`server-hello.ts:55-62`). This is acceptable as
clean rejection, but the README overpromises.

---

## 2. Bug Analysis: Handshake Stall Root Cause

### 2.1 Symptom

All three live TLS 1.3 targets (example.com, cloudflare.com, google.com) stall for exactly
10 seconds (the `DEFAULT_HANDSHAKE_TIMEOUT_MS`), then fail with:
```
TLS handshake failed during finished: handshake timed out after 10000ms
```

### 2.2 Why the Error Message Is Misleading

`withTimeout` (`lifecycle.ts:15-19`) always reports phase `"finished"`:

```typescript
const timeout = clock.sleep(ms).then(() => {
    throw new TlsHandshakeError("finished", {   // ← hardcoded
        cause: new Error(`handshake timed out after ${ms}ms`),
    });
});
```

The `HandshakePhase` union (`errors.ts:30-33`) only has four values:
```typescript
export type HandshakePhase =
    | "client_hello"
    | "server_hello"
    | "certificate"
    | "finished";
```

There is no way to distinguish where the stall actually is. **This is Investigation Blocker #1.**

### 2.3 Root Cause Hypotheses (ranked by likelihood)

#### Hypothesis A: Transport-layer I/O mismatch (MOST LIKELY)

The TLS code uses `transport.read()` via `ensureBytes` (`record-layer.ts:63-72`). The
`FakeTransport` used in sim tests returns data immediately from a pre-seeded queue. With a
real `@browsercore/transport` TCP socket, `transport.read()` returns variable-sized chunks
that may not align with TLS record boundaries.

The `ensureBytes` function handles this correctly in principle (it loops and concatenates).
But there is a subtle behavioral difference:

- **FakeTransport.read()** returns `new Promise<Uint8Array>(() => {})` (never resolves) when
  the queue is empty — this simulates "blocking read."
- **Real transport.read()** may behave differently (e.g., throw on EOF, return zero-length
  buffers, or have different async scheduling).

If `transport.read()` throws instead of hanging when no data is available (e.g., because the
TCP connection was reset), the throw would propagate through `ensureBytes` →
`readEncryptedHandshakeMessage` → `runHandshake` → `withTimeout`. But `withTimeout` races
against the timeout. If the throw happens and the timeout promise hasn't settled yet,
`Promise.race` would settle with the rejection. So a transport throw would NOT produce a
timeout — it would produce a transport error.

**Investigation:** Verify `@browsercore/transport`'s `read()` semantics when no data is
available. Does it block (like FakeTransport)? Does it throw? Does it return after a
transport-level timeout?

#### Hypothesis B: ServerHello session_id / CCS interaction (MODERATE)

Real TLS 1.3 servers in middlebox-compatibility mode:
1. Echo the client's `session_id` in ServerHello (for compatibility)
2. Send a CCS record (type 0x14) between ServerHello and the encrypted flight

The client code sends an **empty session_id** (`client-hello.ts:118`:
`const sessionId = new Uint8Array(0);`). Some servers may behave differently with an empty
session_id vs a random session_id. But RFC 8446 allows empty session_id in TLS 1.3, so this
should not cause a stall.

The CCS handling in `readEncryptedHandshakeMessage` (`handshake-messages.ts:211-230`) is
present and unit-tested. But the **server-sim never sends CCS records**
(`server-sim.ts:357` — responses are `[shRecord, ...encrypted]` with no CCS). This means
the CCS filtering code has **never been tested end-to-end with a full handshake**.

**Investigation:** Add a `sendCcs: true` option to `TlsServerSim` and run the full
handshake test with it. If this fails, the CCS code has a bug that only manifests in the
full flow.

#### Hypothesis C: ClientHello is malformed causing server non-response (MODERATE)

If the ClientHello is structurally invalid or missing a required extension, a real server
may:
1. Silently drop the connection (no response at all → timeout)
2. Send an ALERT record (which the code would handle as a non-HANDSHAKE record → throw, not
   timeout)

A silent drop would explain the timeout. Potential ClientHello issues:
- The `compression_methods` field is `[0x00]` (null only) — correct per §4.1.2
- The `legacy_version` is `0x0303` — correct per §4.1.2
- All required extensions are present (SNI, supported_versions, key_share,
  signature_algorithms)

**Investigation:** Capture the actual ClientHello bytes with a packet sniffer and compare
against what Chrome/curl sends to the same server.

#### Hypothesis D: AEAD decryption failure silently produces garbage (UNLIKELY)

If the key schedule produced wrong traffic keys, AEAD decryption would fail with a tag
mismatch, throwing `TlsDecryptError`. This would propagate as a rejection, NOT a timeout.

The key schedule was verified correct per RFC 8446 §7.1 (confirmed: the `0` IKM for
`Early Secret = HKDF-Extract(0, PSK)` is `Hash.length` zero bytes, not empty, matching
`keySchedule.ts:271-272`). So this hypothesis is unlikely but should be verified with
known-answer test vectors.

#### Hypothesis E: TLS record version field mismatch (LOW)

`serializeRecordHeader` defaults to version `0x0303` for all records. Real TLS 1.3 servers
expect `0x0303` (legacy TLS 1.2 version) in record headers. The code is correct here, but
some strict middleboxes or servers might reject records with unexpected versions. Unlikely
to be the issue.

### 2.4 Recommended Investigation Steps

**Step 1 — Fix timeout attribution (P0, 30 min):**
Change `withTimeout` to accept the current phase, and thread it through the handshake.
Expand `HandshakePhase` to include `encrypted_extensions`, `certificate_verify`, and
`application_data`. This tells us exactly where the stall is.

```
File: src/connection/lifecycle.ts:15-19
File: src/errors.ts:30-33
```

**Step 2 — Add debug tracing (P0, 1 hour):**
Add an optional `onDebug?: (msg: string) => void` callback to `TlsOptions`. Emit a trace
line at each handshake step (before/after transport.read, before/after decrypt, before/after
each message type). Run against example.com:443 and examine the output.

```
File: src/types.ts (add onDebug to TlsOptions)
File: src/connection/handshake-driver.ts (emit trace lines)
File: src/connection/record-layer.ts (emit before/after transport.read)
```

**Step 3 — Add CCS to server-sim (P0, 30 min):**
Add a `sendCcs?: boolean` option to `TlsServerSim`. When true, insert a CCS record between
the ServerHello record and the encrypted flight. Run the full handshake test.

```
File: tests/server-sim.ts:309-358 (onClientHello method)
```

**Step 4 — Test key schedule with known vectors (P1, 1 hour):**
Use the published RFC 8446 Appendix B test vectors or the OpenSSL `SSLKEYLOGFILE` format
to verify that the client's key schedule output matches a reference implementation.

```
File: tests/keySchedule.test.ts (add known-answer tests)
```

**Step 5 — Verify transport.read() semantics (P1, 30 min):**
Check whether `@browsercore/transport`'s `read()` blocks indefinitely (like FakeTransport)
or has a transport-level timeout/EOF behavior. Read the transport source.

```
Dependency: ../browsercore-transport/src/
```

**Step 6 — Capture and compare ClientHello (P1, 30 min):**
Run `RUN_LIVE_TESTS=1 npx vitest run tests/live-handshake.test.ts` with a packet capture.
Compare the ClientHello bytes against what `curl --tlsv1.3 https://example.com` produces.

---

## 3. Architecture Recommendations

### 3.1 Split `HandshakePhase` from Error Phase

**Problem:** `HandshakePhase` (`errors.ts:30-33`) only has four coarse values
(`client_hello | server_hello | certificate | finished`). The actual handshake has more
granular phases (encrypted_extensions, certificate_verify, key_exchange, etc.). All timeout
and state errors are forced into one of these four buckets, destroying diagnostic value.

**Recommendation:** Expand `HandshakePhase` to match the real state machine phases:
```typescript
export type HandshakePhase =
    | "init"
    | "client_hello"        // building/sending ClientHello
    | "server_hello"        // reading/parsing ServerHello
    | "key_exchange"        // (EC)DHE + traffic secret derivation
    | "encrypted_extensions"
    | "certificate"
    | "certificate_verify"
    | "finished"            // server Finished verification
    | "client_finished"     // client Finished construction/sending
    | "application";        // post-handshake
```

### 3.2 Add CertificateVerify Verification Step

**Problem:** The `consumeServerFlight` function in `handshake-driver.ts:282-285` reads
CertificateVerify and pushes it to the transcript but never verifies the signature. The
`verifyChain` function in `certificates.ts` verifies the chain signatures (issuer → subject)
but does NOT verify the CertificateVerify (which proves the server owns the private key
corresponding to the leaf certificate).

**Recommendation:** Add a `verifyCertificateVerify()` function to
`connection/handshake-messages.ts` or `connection/key-exchange.ts` that:
1. Extracts the signature scheme and signature from the CertificateVerify body
2. Constructs the signed content: 64 bytes of `0x20` (space) repeated 64 times, followed by
   `"TLS 1.3, server CertificateVerify"`, followed by `\x00`, followed by the transcript hash
   of ClientHello..Certificate (RFC 8446 §4.4.3)
3. Calls `provider.verifySignature()` with the leaf certificate's SPKI, the signature, and
   the signed content
4. Throws `TlsHandshakeError("certificate_verify")` on mismatch

```
File: src/connection/handshake-messages.ts (new function)
File: src/connection/handshake-driver.ts:282-285 (call the new function)
```

### 3.3 Extract CertificateVerify Content Construction

The CertificateVerify signed content (RFC 8446 §4.4.3) is:
```
64 * 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || Hash(transcript)
```

This should be a pure function in `connection/handshake-messages.ts`, testable in isolation.

### 3.4 Add Record Layer Validation

**Problem:** `readRawRecord` (`record-layer.ts:88-107`) trusts the record length field
without bounds checking. `parseRecordHeader` (`record/record.ts:136-153`) does not validate
the record version field. This creates a memory safety risk with malicious or buggy servers.

**Recommendation:** Add validation in `parseRecordHeader`:
- Length must be ≤ `MAX_PLAINTEXT_FRAGMENT + 256` (encrypted max, per §5.1)
- Length must be > 0 for non-CCS records
- Version should be `0x0303` (legacy TLS 1.2) or `0x0301` (legacy TLS 1.0, for middlebox
  compatibility)

### 3.5 Post-Handshake Record Handling Needs Hardening

**Problem:** `handlePostHandshakeRecord` in `lifecycle.ts:34-52` silently ignores all
post-handshake HANDSHAKE messages. This means:
- `NewSessionTicket` is silently dropped (no session cache update)
- `KeyUpdate` is silently dropped (no key rotation)
- `CertificateRequest` (post-handshake auth) is silently dropped

The application-data `read()` loop in `tls.ts:290-310` also doesn't handle CCS records
in the post-handshake phase (it uses `readEncryptedRecord`, not
`readEncryptedHandshakeMessage`).

**Recommendation:** At minimum, `KeyUpdate` must be handled (RFC 8446 §4.6.3 mandates
that the receiver update their traffic keys). The `updateTrafficSecrets` function already
exists in `keySchedule.ts:370-380` — it just needs wiring.

### 3.6 Server Simulator Should Mirror Real Server Behavior

**Problem:** `TlsServerSim` (`tests/server-sim.ts`) is the primary integration test tool.
It does NOT send CCS records (`server-sim.ts:357`). It sends a dummy CertificateVerify
signature (`server-sim.ts:246-248`). It sends a self-signed certificate, not a chain.
This means the sim never exercises the code paths that real servers trigger.

**Recommendation:** Add options to `ServerOptions`:
- `sendCcs?: boolean` — insert a CCS record before the encrypted flight
- `certificateChain?: Certificate[]` — send leaf + intermediate + root
- `realCertificateVerify?: boolean` — compute a real CertificateVerify signature
- `helloRetryRequest?: NamedGroup` — send HRR with a different group

### 3.7 TLS 1.2 References Should Be Removed or Implemented

**Problem:** The README (`README.md:5-6`), `tls.ts` header comment (`tls.ts:9-11`), and
`profiles.ts` (`profiles.ts:55`) all reference `runTls12Handshake()` and "TLS 1.2 fallback"
as if it exists. It does not — the function is never defined, and TLS 1.2 is explicitly
rejected. This is misleading documentation.

**Recommendation:** Either:
- **(Recommended)** Remove all TLS 1.2 references from docs/comments and document the clean
  rejection behavior as intentional.
- **(Future)** Implement TLS 1.2 as a separate `runTls12Handshake()` function with its own
  record layer (CBC mode, different key derivation, MD5+SHA1 PRF). This is a large effort.

### 3.8 Connection Close on Error

**Problem:** When `runHandshake` throws (any error), the transport is NOT closed. The
`performHandshake` method (`tls.ts:379-395`) doesn't have a try/finally. If the caller
doesn't explicitly call `close()`, the socket leaks.

**Recommendation:** Wrap `performHandshake` in a try/catch. On any error, attempt to send
a fatal alert and close the transport before re-throwing.

---

## 4. Implementation Phases

### Phase 0: Debug the Stall (BLOCKING — must complete first)

**Goal:** Determine the exact root cause of the handshake timeout against real servers.

**Rationale:** All subsequent work is pointless if the handshake doesn't complete. The fixes
for CCS (0.4.3) and coalesced messages (0.4.3) are present in the code but the stall
persists — meaning there is at least one more bug.

**Tasks:**
1. Expand `HandshakePhase` and fix `withTimeout` to report the real stall location
   - `errors.ts:30-33` — expand the union
   - `lifecycle.ts:15-19` — accept and thread the current phase
   - `handshake-driver.ts` — pass the correct phase at each step
2. Add a `debug?: (msg: string) => void` callback to `TlsOptions` and emit traces
   - `types.ts` — add `onDebug` to `TlsOptions`
   - `handshake-driver.ts` — emit at each step
   - `record-layer.ts` — emit before/after `transport.read()`
3. Add `sendCcs` option to `TlsServerSim` and test the full handshake with CCS
   - `tests/server-sim.ts` — add CCS to `onClientHello`
4. Run `RUN_LIVE_TESTS=1 npx vitest run tests/live-handshake.test.ts` with debug tracing
5. Based on the output, identify and fix the root cause

**Files to touch:**
- `src/errors.ts`
- `src/types.ts`
- `src/connection/lifecycle.ts`
- `src/connection/handshake-driver.ts`
- `src/connection/record-layer.ts`
- `tests/server-sim.ts`

**Testing strategy:** Run the live handshake test with `RUN_LIVE_TESTS=1`. The expanded
phase reporting will show exactly where the stall is.

**Risk:** LOW — these are diagnostic changes only. No protocol behavior changes.

---

### Phase 1: Critical Security Fixes (BLOCKING for production use)

**Goal:** Close the two security vulnerabilities that make the handshake insecure even when
it completes.

**Prerequisites:** Phase 0 complete (handshake completes against real servers).

#### 1A. Implement CertificateVerify Verification

**RFC reference:** §4.4.3

**Tasks:**
1. Add `verifyCertificateVerify()` to `connection/handshake-messages.ts`:
   - Parse the body: `signature_scheme(2) || signature_length(2) || signature(N)`
   - Construct the to-be-signed content:
     ```
     String(64 bytes of 0x20) || "TLS 1.3, server CertificateVerify" || 0x00 || TranscriptHash(ClientHello..Certificate)
     ```
   - Map the signature scheme to the `verifySignature` call
   - Use the leaf certificate's SPKI as the verification key
2. Call it from `handshake-driver.ts:282-285` after pushing CertificateVerify to the
   transcript
3. Update `TlsServerSim` to generate a REAL CertificateVerify signature (using its ECDSA
   private key) so the verification actually exercises the crypto

**Files to touch:**
- `src/connection/handshake-messages.ts` — new function
- `src/connection/handshake-driver.ts:282-285` — call the function
- `src/errors.ts` — add `certificate_verify` to `HandshakePhase`
- `tests/server-sim.ts:242-249` — real signature
- `tests/handshake-driver.test.ts` — test verification success and failure

**Testing strategy:**
- Unit test: construct a CertificateVerify with a known signature and verify it
- Integration test: server-sim with real ECDSA signature
- Negative test: tamper the signature, assert `TlsHandshakeError("certificate_verify")`
- The sim test for tampered Finished (`handshake-driver.test.ts:189-200`) already tests
  a similar flow — follow that pattern

**Risk:** MEDIUM — the CertificateVerify content construction must be byte-exact.
Off-by-one errors in the content string or transcript hash will cause verification failures
against real servers. Test with known test vectors.

#### 1B. Implement Downgrade Protection

**RFC reference:** §4.1.3

**Tasks:**
1. After parsing the ServerHello, check the last 8 bytes of `random`:
   - If `random[24..32]` == `44 4F 57 4E 47 52 44 01` → `illegal_parameter` (TLS 1.2
     downgrade attempt)
   - If `random[24..32]` == `44 4F 57 4E 47 52 44 00` → `illegal_parameter` (TLS 1.1 or
     below downgrade attempt)
2. Add the check in `server-hello.ts:parseServerHello()` after parsing `random`

**Files to touch:**
- `src/handshake/server-hello.ts:121-123` — add sentinel check
- `tests/server-hello.test.ts` — test sentinel detection

**Testing strategy:** Construct ServerHello messages with the sentinel bytes and verify
rejection. Construct normal ServerHello and verify acceptance.

**Risk:** LOW — straightforward comparison.

---

### Phase 2: Protocol Completeness (IMPORTANT for interoperability)

**Goal:** Handle the TLS 1.3 features that real servers commonly exercise.

**Prerequisites:** Phase 1 complete.

#### 2A. Implement HelloRetryRequest

**RFC reference:** §4.1.3, §4.2.2

**Tasks:**
1. After parsing ServerHello, check for the HRR sentinel random
   (`CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A23721`)
2. If HRR is detected:
   - Parse the HRR extensions (selected_group, cookie)
   - Generate a new key share for the server's selected group
   - Add a synthetic `message_hash` message to the transcript (RFC 8446 §4.4.1)
   - Rebuild and resend the ClientHello with the new key share and cookie
   - Read the real ServerHello that follows
3. Handle the `cookie` extension (echo it back in the new ClientHello)

**Files to touch:**
- `src/handshake/server-hello.ts` — HRR detection
- `src/connection/handshake-driver.ts` — HRR loop (steps 2-4 of runHandshake)
- `src/handshake/client-hello.ts` — support cookie extension
- `src/handshake/handshake-types.ts` — HRR type

**Testing strategy:**
- Unit test: detect HRR sentinel, parse HRR extensions
- Integration test: server-sim sends HRR requesting secp256r1, client responds correctly
- Transcript hash must include the synthetic message_hash

**Risk:** MEDIUM — the transcript hash manipulation (synthetic message_hash) is subtle and
must be byte-exact. Test against known HRR test vectors.

#### 2B. Implement KeyUpdate Handling

**RFC reference:** §4.6.3

**Tasks:**
1. Parse `KeyUpdate` messages in `handlePostHandshakeRecord`
2. Derive new traffic secrets using `updateTrafficSecrets` (already exists)
3. Update the connection's `applicationSecrets` and reset the appropriate sequence counter
4. If `KeyUpdate.request_update` is `update_requested`, send our own KeyUpdate

**Files to touch:**
- `src/connection/lifecycle.ts:38-44` — parse KeyUpdate instead of ignoring
- `src/tls.ts` — apply new traffic secrets, reset seq counters
- `src/types.ts` — expose mutable application secrets on `TlsConnectionImpl`

**Testing strategy:**
- Unit test: `updateTrafficSecrets` produces correct next-secret
- Integration test: send KeyUpdate during application data phase, verify key rotation

**Risk:** LOW — the crypto derivation already exists and is tested. The wiring is
straightforward.

#### 2C. Implement Alert Sending

**RFC reference:** §6

**Tasks:**
1. Add a `sendAlert(level, description)` method to `TlsConnectionImpl`
2. Call it before throwing on protocol errors (bad ServerHello, bad Finished, cert failure)
3. Map each error type to the appropriate alert description:
   - `handshake_failure` (40) — bad cipher suite, bad version
   - `bad_certificate` (42) — cert validation failure
   - `decrypt_error` (51) — Finished verify_data mismatch
   - `illegal_parameter` (47) — downgrade sentinel, unexpected message
   - `internal_error` (80) — unexpected exceptions

**Files to touch:**
- `src/tls.ts` — add `sendAlert()` and call it in error paths
- `src/connection/handshake-driver.ts` — call `sendAlert` before throwing
- `src/errors.ts` — add alert description constants

**Testing strategy:**
- Verify the alert record is written to the transport before the error is thrown
- Verify the transport is closed after a fatal alert

**Risk:** LOW — straightforward I/O wrapping.

#### 2D. Connection Cleanup on Error

**Tasks:**
1. Wrap `performHandshake` in try/catch
2. On any error: attempt to send a fatal alert, close the transport, transition to `closed`
3. Re-throw the original error

**Files to touch:**
- `src/tls.ts:379-395` (`performHandshake`)

**Risk:** LOW.

---

### Phase 3: Session Management & Performance (IMPORTANT for production)

**Goal:** Enable session resumption for connection reuse.

**Prerequisites:** Phase 2 complete.

#### 3A. NewSessionTicket Consumption & Session Cache

**RFC reference:** §4.6.1

**Tasks:**
1. Parse `NewSessionTicket` messages in the post-handshake path
2. Derive the resumption master secret: `HKDF-Expand-Label(master_secret, "res master", Transcript-Hash(ClientHello..client Finished), Hash.length)`
3. Compute the PSK from the ticket: `HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`
4. Store `(ticket, psk, cipher_suite, max_early_data_size)` in a session cache
5. Expose a `TlsSession` type that callers can pass to `connectTls` for resumption

**Files to touch:**
- `src/connection/lifecycle.ts` — parse NewSessionTicket
- `src/crypto/keySchedule.ts` — add `deriveResumptionMasterSecret()`
- `src/types.ts` — add `TlsSession` type
- `src/tls.ts` — thread session cache

**Risk:** MEDIUM — session resumption is complex (PSK binder computation, early data).
Can be staged: first consume tickets and cache them, then offer PSK in later handshakes.

#### 3B. Session Resumption (PSK)

**RFC reference:** §2.2

**Tasks:**
1. When a cached session exists for the target server, offer it via `pre_shared_key`
   extension in ClientHello
2. Compute the PSK binder: `HMAC(finished_key, Transcript-Hash(truncated ClientHello))`
3. Use the PSK as the early secret IKM in the key schedule
4. Handle PSK negotiation in ServerHello

**Risk:** HIGH — PSK binder computation is the most complex part of TLS 1.3. Requires
careful transcript handling. Test against known test vectors.

---

### Phase 4: Advanced Features (LATER)

These are lower-priority features for completeness:

- **0-RTT early data** (§2.3, §8) — requires PSK first
- **Certificate compression** (RFC 8879) — advertised but not processed
- **OCSP stapling** (RFC 6066 §8) — advertised but not processed
- **Certificate Transparency** (RFC 6962) — not implemented
- **Mutual TLS** (client certificates) — not implemented
- **Post-handshake authentication** (§4.6.2) — not implemented
- **Record size limit** (RFC 8449) — not negotiated
- **TLS 1.2 fallback** — clean rejection only; full implementation is a major effort
- **Ed25519 signature verification** — requires crypto backend support
- **secp521r1 / x448 / FFDHE key exchange** — requires crypto backend support

---

## 5. Effort Summary

| Phase | Tasks | Estimated Effort | Priority |
|-------|-------|-----------------|----------|
| 0 — Debug the stall | 5 tasks | 1-2 days | BLOCKING |
| 1A — CertificateVerify verification | 3 tasks | 1-2 days | P0 (security) |
| 1B — Downgrade protection | 1 task | 0.5 days | P1 |
| 2A — HelloRetryRequest | 3 tasks | 2-3 days | P1 |
| 2B — KeyUpdate | 3 tasks | 1 day | P2 |
| 2C — Alert sending | 2 tasks | 1 day | P2 |
| 2D — Error cleanup | 1 task | 0.5 days | P2 |
| 3A — Session cache | 5 tasks | 2-3 days | P3 |
| 3B — PSK resumption | 4 tasks | 3-5 days | P3 |
| 4 — Advanced features | varies | 2-3 weeks | P4 |

**Total to production-quality TLS 1.3 (Phases 0-2):** ~2 weeks for one specialist agent.

---

## Appendix A: Known Correct Items (no work needed)

These items were reviewed and found correct:

- **Key schedule** (§7.1) — `early_secret = HKDF-Extract(0, 0)` where `0` = `Hash.length`
  zero bytes (confirmed against RFC 8446 §7.1: "the 0-value consisting of a string of
  Hash.length bytes set to zeros"). Code at `keySchedule.ts:270-272` matches.
- **HKDF-Expand-Label** — correct label prefix (`"tls13 "`), correct struct layout
  (`keySchedule.ts:200-226`).
- **Per-record nonce** — correct XOR of sequence number into the IV's trailing 8 bytes
  (`record-layer.ts:41-57`).
- **Inner content type stripping** — correct backward scan for trailing non-zero byte
  (`record-layer.ts:128-147`).
- **Constant-time comparison** — correct XOR-accumulate pattern (`utils.ts:26-44`).
- **GREASE generation** — correct 0x?a?a set, uniform random selection
  (`client-hello.ts:34-66`).
- **Coalesced handshake splitting** — correct 4-byte header + 24-bit length walk
  (`handshake-messages.ts:151-190`).
- **Hostname validation** — correct SAN-first, CN-fallback, wildcard matching
  (`hostname.ts:18-48`).
- **Certificate chain verification** — correct per-cert signature check, SPKI anchor match
  (`certificates.ts:268-351`).
- **DER parsing** — correct TLV decoding, OID parsing, time parsing (`der.ts`).
- **Extension parsing** — correct length-prefixed list walk (`extensions.ts:72-119`).

---

## Appendix B: Test Coverage Gaps

| Area | Current Coverage | Gap |
|------|-----------------|-----|
| Key schedule | Structural only | No known-answer test vectors |
| CertificateVerify | Not tested | Function doesn't exist |
| CCS + full handshake | Unit only | Never tested in full handshake flow (sim doesn't send CCS) |
| AES-128-CCM | Untested live | Only GCM and ChaCha20 tested |
| secp256r1/secp384r1 | Unit tested | Not tested in full handshake (profile filters them out at `handshake-driver.ts:131`) |
| RSA-PSS cert chain | Untested | Sim uses self-signed ECDSA only |
| Alert handling (sent) | Untested | Client never sends protocol alerts |
| KeyUpdate | Untested | Not implemented |
| HRR | Untested | Not implemented |
| Malformed ServerHello | Partial | No fuzz testing |

---

## Appendix C: File Inventory

### Source files (26 files)

| Path | Lines | Role |
|------|-------|------|
| `src/tls.ts` | 430 | Public API: `connectTls()`, `TlsConnectionImpl` coordinator |
| `src/types.ts` | 295 | Domain types, `TlsOptions`, `ClientHelloConfig` |
| `src/errors.ts` | 163 | Typed error hierarchy, `HandshakePhase` |
| `src/utils.ts` | 48 | `assertNever`, `createId`, `constantTimeEqual` |
| `src/index.ts` | 100 | Public API barrel exports |
| `src/record/record.ts` | 265 | Record framing, AEAD encrypt/decrypt dispatch |
| `src/crypto/keySchedule.ts` | 404 | Full TLS 1.3 key schedule (§7.1) |
| `src/handshake/client-hello.ts` | 470 | ClientHello serialization |
| `src/handshake/server-hello.ts` | 183 | ServerHello parsing + negotiation |
| `src/handshake/state-machine.ts` | 130 | Handshake phase transitions |
| `src/handshake/handshake-types.ts` | 84 | Shared handshake types |
| `src/handshake/handshake.ts` | 41 | Handshake module barrel |
| `src/extensions/extensions.ts` | 234 | Extension types, parsers, wire encoders |
| `src/certificates/certificates.ts` | 356 | X.509 parse, chain verify |
| `src/certificates/hostname.ts` | 49 | RFC 6125 hostname matching |
| `src/certificates/der.ts` | 228 | DER TLV parsing primitives |
| `src/certificates/pem.ts` | 72 | PEM decoding |
| `src/certificates/cert-extensions.ts` | 214 | X.509 extension parsing (SAN, KeyUsage, etc.) |
| `src/connection/handshake-driver.ts` | 295 | Handshake choreography |
| `src/connection/handshake-messages.ts` | 257 | Server-flight message parsing |
| `src/connection/record-layer.ts` | 173 | Record I/O, nonce, buffer management |
| `src/connection/key-exchange.ts` | 126 | (EC)DHE, transcript hash, Finished verify |
| `src/connection/lifecycle.ts` | 84 | Timeout, alert, state transitions |
| `src/connection/index.ts` | 30 | Connection module barrel |
| `src/iana/*.ts` | ~80 | IANA registry tables (cipher suites, groups, schemes, versions) |
| `src/profiles/profiles.ts` | 100 | Placeholder TLS profiles |

### Test files (32 files)

Key test files for coverage:
- `tests/handshake-driver.test.ts` — full handshake integration via sim
- `tests/server-sim.ts` — minimal TLS 1.3 server simulator
- `tests/keySchedule.test.ts` — key schedule unit tests
- `tests/ccs-filter.test.ts` — CCS filtering unit tests
- `tests/record-layer.test.ts` — record I/O round-trip tests
- `tests/tls-connection.test.ts` — public API surface tests
- `tests/live-handshake.test.ts` — live server test (gated behind `RUN_LIVE_TESTS=1`)
