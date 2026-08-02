# @browsercore/tls

A TLS 1.3 (and 1.2 fallback) client implemented entirely in TypeScript.

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
import { connect } from "@browsercore/transport";
import { connectTls, resolveProfile, TlsHandshakeError } from "@browsercore/tls";

const transport = await connect({ host: "example.com", port: 443 });

const tls = await connectTls({
    transport,
    serverName: "example.com",
    profile: resolveProfile("modern-tls13", "example.com"),
    alpnProtocols: ["h2", "http/1.1"],
    handshakeTimeoutMs: 10_000,
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
| `TlsState` | discriminated union | `connecting \| handshaking \| open \| closed` |
| `CloseReason` | discriminated union | Why a TLS connection closed |
| `ProtocolVersion` | discriminated union | `TLS 1.2` / `TLS 1.3` with wire codes |
| `CipherSuite` | string-literal union | Negotiated AEAD + hash |
| `ClientHelloConfig` | interface | ClientHello configuration (placeholder for @browsercore/profiles) |
| `TlsError` | class | Base typed error |
| `TlsHandshakeError` | class | Handshake failure at a specific phase |
| `TlsDecryptError` | class | Record decryption / auth failure |
| `TlsAlertError` class | TLS alert with level + description |

## Dependency graph

```
@browsercore/tls
  └─ @browsercore/transport  @browsercore/crypto
```

No other `@browsercore/*` packages are imported.
