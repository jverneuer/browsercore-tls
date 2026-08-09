# @browsercore/tls

[![npm version](https://img.shields.io/npm/v/@browsercore/tls)](https://www.npmjs.com/package/@browsercore/tls)
[![coverage](https://img.shields.io/endpoint?url=https://jverneuer.github.io/browsercore-tls/badge.json)](https://github.com/jverneuer/browsercore-tls/blob/main/COVERAGE.md)
[![lint](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-tls/ci.yml?label=lint)](https://github.com/jverneuer/browsercore-tls/actions/workflows/ci.yml)

A TLS 1.3 client implemented entirely in TypeScript, with optional TLS 1.2
fallback (RFC 5246). TLS 1.2 support is gated behind server negotiation: if the
server selects a TLS 1.2 cipher suite, the handshake driver branches to
runTls12Handshake(). Requesting a TLS 1.2-only handshake (one that cannot
negotiate TLS 1.3) is rejected up front with a typed error.

## Responsibility

Owns the full TLS handshake, record layer, key schedule, and X.509 certificate
validation. Provides an encrypted byte stream over an existing
`@browsercore/transport` connection so higher layers never touch plaintext on the wire.

## What it does NOT know about

- HTTP (any version)
- Browser fingerprints
- Cookies

It knows about byte streams (`@browsercore/transport`) and cryptographic primitives
(`@browsercore/crypto`). It **never** imports `node:crypto` directly — that boundary
is `@browsercore/crypto`'s job, which keeps the crypto backend replaceable.

## Public API

```ts
import { EventEmitter } from "node:events";
import { connect } from "@browsercore/transport";
import { connectTls, resolveProfile, TlsHandshakeError } from "@browsercore/tls";

const transport = await connect({ host: "example.com", port: 443 });

// `events` is required — an injected EventProvider backend that decouples the
// connection from node:events. Any runtime adapter satisfying the EventProvider
// interface works (here a thin wrapper over Node's EventEmitter).
const events = new EventEmitter();
const tls = await connectTls({
    transport,
    serverName: "example.com",
    profile: resolveProfile("modern-tls13", "example.com"),
    alpnProtocols: ["h2", "http/1.1"],
    handshakeTimeoutMs: 10_000,
    events,
});

const response = await tls.read();
await tls.write(new TextEncoder().encode("GET / HTTP/1.1\r\n"));
await tls.close();
```

## Types

| Export | Kind | Purpose |
| --- | --- | --- |
| `TlsConnection` | interface | Public contract higher layers depend on |
| `connectTls()` | function | Perform the TLS handshake over a transport |
| `TlsConnectionImpl` | class | Concrete connection (thin coordinator over `./connection/` modules) |
| `TlsState` | discriminated union | `connecting \| handshaking \| open \| closed` |
| `CloseReason` | discriminated union | Why a TLS connection closed |
| `ProtocolVersion` | discriminated union | `TLS 1.2` / `TLS 1.3` with wire codes |
| `CipherSuite` | string-literal union | Negotiated AEAD + hash |
| `ClientHelloConfig` | interface | ClientHello configuration (placeholder for @browsercore/profiles) |
| `TlsProfile` | interface | Named, reusable ClientHello config |
| `resolveProfile()` | function | Look up a profile by name and fill in serverName |
| `TlsError` | class | Base typed error |
| `TlsHandshakeError` | class | Handshake failure at a specific phase |
| `TlsDecryptError` | class | Record decryption / auth failure |
| `TlsAlertError` | class | TLS alert with level + description |

## Dependency graph

```
@browsercore/tls
  ├─ @browsercore/contracts
  ├─ @browsercore/transport
  └─ @browsercore/crypto
```

`@browsercore/contracts` provides the `EventProvider` interface the connection
composes (dependency injection — no `node:events` import). Shared build, lint,
and test config comes from `@browsercore/dev` (see [Development](#development)).

## Architecture

The package is a thin coordinator + focused pure-function modules. The
connection class (`TlsConnectionImpl`) owns mutable state (read buffer,
transcript, traffic secrets, sequence counters) and the public surface
(`handshake` / `read` / `write` / `close` / `on`). Every byte-level computation
lives in a module under `src/connection/` and is written as functions over
explicit inputs, so the protocol logic is unit-testable without a live
connection.

| Module | Responsibility |
| --- | --- |
| `src/record/record.ts` | Record header parse/serialize, AEAD encrypt/decrypt (delegates to `@browsercore/crypto`) |
| `src/handshake/client-hello.ts` | ClientHello builder (SNI, supported_versions, key_share, signature_algorithms, ALPN) |
| `src/handshake/server-hello.ts` | ServerHello parser — validates cipher suite + version |
| `src/handshake/state-machine.ts` | Handshake phase state machine with phase-tagged errors |
| `src/crypto/keySchedule.ts` | TLS 1.3 key schedule (RFC 8446 §7.1): HKDF-Expand-Label, traffic secrets |
| `src/certificates/` | X.509 DER parse, hostname validation (RFC 6125), chain verification |
| `src/extensions/` | Extension types, parsers, and wire encoders |
| `src/connection/handshake-driver.ts` | Handshake choreography (what to send, what to read, when to derive) |
| `src/connection/record-layer.ts` | TLS 1.3 inner-content-type wrapping, nonce XOR, record framing |
| `src/connection/key-exchange.ts` | (EC)DHE shared secret, transcript hash, server Finished verification |
| `src/connection/handshake-messages.ts` | EncryptedExtensions/Certificate/Finished parsing, client Finished builder |
| `src/connection/lifecycle.ts` | Timeouts, alerts, state transitions, post-handshake record dispatch |

Errors all carry a `kind` discriminator so callers can narrow and inspect
without leaking backend specifics (`TlsHandshakeError(phase)`,
`TlsDecryptError`, `TlsAlertError(level, description)`).

## Not implemented

- Post-handshake messages (NewSessionTicket, KeyUpdate)
- Session resumption / PSK / 0-RTT
- Mutual TLS (client certificate)
- Certificate compression
- HelloRetryRequest
- Additional key-share groups beyond X25519

## Development

This repo shares tooling with the `@browsercore/*` family via
[`@browsercore/dev`](https://www.npmjs.com/package/@browsercore/dev). That package
is the single source of truth for:

- `tsconfig` strict flags — `tsconfig.json` extends `@browsercore/dev/tsconfig.base.json`
- `vitest` config — `vitest.config.ts` imports `definePackageConfig` from `@browsercore/dev/vitest`
- `oxlint` config — `oxlint.config.ts` imports the base ruleset from `@browsercore/dev/oxlint`
- `coverage-md` bin — shipped via `@browsercore/dev`'s `bin/`, used as `npx coverage-md`

`@browsercore/dev` is declared in `devDependencies` as `"file:../dev"` for local
development (the monorepo layout). When installing from npm, consumers resolve the
published version.

### Scripts

```sh
npm run typecheck   # tsc --noEmit (strict mode — noUncheckedIndexedAccess, exactOptionalPropertyTypes)
npm run lint        # oxlint --type-aware src/ (tests excluded)
npm test            # vitest run (in-process fixture server, no real network)
npm run build       # tsc -p tsconfig.build.json → dist/
npx coverage-md     # write COVERAGE.md + coverage/badge.json from coverage-summary.json
```

Run a single test file:

```sh
npx vitest run tests/handshake.test.ts
```

Run tests by name pattern:

```sh
npx vitest run -t "rejects a non-browser User-Agent"
```

### Lint config

Linting is type-aware oxlint via `oxlint.config.ts`. The file extends the shared
`@browsercore/dev/oxlint` base (which enables the `typescript`, `unicorn`, `import`,
`promise`, and `node` plugins with `correctness`/`suspicious`/`pedantic` as errors).
The old `.oxlintrc.json` has been removed.

Private fields use the native TypeScript `private` keyword — the legacy
`_`-prefixed naming convention has been fully migrated away, so no
`no-underscore-dangle` allowlist is required.

Requires **Node >= 26**. ESM only (`"type": "module"`).
