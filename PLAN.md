# @browsercore/tls — Implementation Plan

A TLS 1.3 (with 1.2 fallback) client over `@browsercore/transport`. Implement in this
order; each step is independently testable. All crypto goes through
`@browsercore/crypto` — never `node:crypto` directly.

## Step 1 — Record layer parse/serialize

Implement `parseRecordHeader` and `serializeRecordHeader` in `src/record/record.ts`
(already stubbed with full types). These are pure functions — unit-testable with a
round-trip assertion.

Tests: serialize → parse round-trip for each `ContentType`; reject truncated buffers
and invalid content types with `TlsDecryptError`.

## Step 2 — ClientHello builder + parser round-trip

Implement `buildClientHello` and the helpers it needs:

1. Generate key shares via `@browsercore/crypto` for each group in the profile.
2. Serialize client_version (0x0303), random (32 bytes), session_id, cipher_suites,
   compression_methods (0x00), and the extensions block.
3. Extensions: SNI, supported_versions, key_share, signature_algorithms, ALPN.

Tests: build a ClientHello, parse the handshake body back, assert all fields match.

## Step 3 — ServerHello parser

Implement `parseServerHello` in `src/handshake/handshake.ts`. Validate the selected
cipher suite is one we offered and the version is supported, throwing
`TlsHandshakeError("server_hello")` otherwise.

Tests: parse a hand-crafted ServerHello; assert rejection on an unoffered cipher suite.

## Step 4 — X.509 parse + hostname validation

Implement `parseCertificate`, `validateHostname`, and `verifyChain` in
`src/certificates/certificates.ts`:

1. ASN.1 decode of the certificate (TBSCertificate + signatureAlgorithm + signatureValue).
2. Hostname validation per RFC 6125 (SAN DNS names first, wildcard-aware, CN fallback).
3. Chain verification: validity windows, basicConstraints, and signature verification
   delegated to `@browsercore/crypto`.

Tests: parse a real DER certificate; assert hostname match/mismatch; assert an expired
chain is rejected.

## Step 5 — Key schedule (HKDF)

Implement the TLS 1.3 key schedule in `src/crypto/keySchedule.ts`:

1. `hkdfExpandLabel` over the @browsercore/crypto HKDF primitives.
2. `deriveHandshakeSecrets` (RFC 8446 §7.1) from the (EC)DHE shared secret.
3. `deriveApplicationSecrets` from the master secret.

Tests: verify against the RFC 8446 test vectors (no network needed).

## Step 6 — Handshake state machine wiring

Implement `advanceHandshake` and the full `connectTls` flow:

1. Drive `TlsState` through `connecting → handshaking → open → closed`.
2. Wire the record layer, handshake messages, and key schedule together.
3. Map every failure to a typed error (`TlsHandshakeError` with the right phase,
   `TlsAlertError` for peer alerts).

Tests: drive the state machine through the happy path and through each failure phase.

## Step 7 — Record encryption/decryption

Implement `encryptRecord` / `decryptRecord` in `src/record/record.ts` by calling the
AEAD primitives from `@browsercore/crypto`. Handle TLS 1.3 inner content-type wrapping and
the TLS 1.2 CBC/AEAD record formats.

Tests: encrypt → decrypt round-trip; assert tampering fails authentication.

## Step 8 — Full TLS 1.3 handshake against a test server

Integration test: spin up a TLS 1.3 server (e.g. `openssl s_server` or a Node `tls`
server with minVersion TLS 1.3) over a loopback `@browsercore/transport` and run a full
handshake + application-data exchange.

## Step 9 — TLS 1.2 fallback

When the server does not support TLS 1.3 (supported_versions absent or only 1.2),
negotiate TLS 1.2 using the same record layer with the TLS 1.2 key schedule and
CBC/AEAD record protection.

## Step 10 — ALPN + SNI

Assert the server's selected ALPN protocol matches what we offered; surface it on
`TlsConnection.alpnProtocol`. End-to-end test negotiating "h2".

## Definition of done

- [ ] Record header parse/serialize round-trips and rejects malformed input.
- [ ] ClientHello builds and parses back losslessly.
- [ ] ServerHello parser validates cipher suite + version.
- [ ] X.509 certificates parse; hostname validation follows RFC 6125.
- [ ] Chain verification delegates signatures to @browsercore/crypto.
- [ ] Key schedule matches RFC 8446 test vectors.
- [ ] Handshake state machine reaches a terminal state (`open` or `closed`) on every path.
- [ ] Record encryption/decryption round-trips; tampering is detected.
- [ ] Full TLS 1.3 handshake succeeds against a test server.
- [ ] TLS 1.2 fallback works against a TLS 1.2-only server.
- [ ] ALPN negotiation selects the expected protocol.
- [ ] Every test in `tests/` passes; `tsc --build` is clean.
- [ ] No import of `node:crypto` anywhere in this package.
