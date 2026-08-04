/**
 * TLS handshake protocol (RFC 8446 §4, RFC 5246 §7) — module barrel.
 *
 * Builds and parses the handshake messages and drives the handshake state
 * machine. Cryptographic operations (key generation, signing, verification) are
 * delegated to @browsercore/crypto; this module owns message layout and state
 * transitions only.
 *
 * The work is split across focused submodules, each responsible for one layer:
 *   - `handshake-types.ts` — shared types (ClientHello, ServerHello, HandshakePhase)
 *     and the HandshakeType constants. Imported by every other submodule so they
 *     agree on shapes without cycling through this barrel.
 *   - `client-hello.ts`    — ClientHello serialization (the only place that knows
 *     the client's opening-message wire layout).
 *   - `server-hello.ts`    — ServerHello parsing + version/cipher negotiation.
 *   - `state-machine.ts`   — the handshake phase transitions and predicates.
 *
 * This file re-exports them so callers have a single stable import path
 * (`./handshake/handshake.js`); it deliberately holds no logic of its own.
 */

export {
    HandshakeType,
    type ClientHello,
    type ServerHello,
    type HandshakePhase,
} from "./handshake-types.js";
export { buildClientHello, cipherSuiteToWire, ALL_CIPHER_SUITES, isCipherSuite } from "./client-hello.js";
export { parseServerHello, type ServerHelloValidation } from "./server-hello.js";
export {
    advanceHandshake,
    recordServerHello,
    completeHandshake,
    isKeyShareGroup,
    isTls13,
} from "./state-machine.js";
