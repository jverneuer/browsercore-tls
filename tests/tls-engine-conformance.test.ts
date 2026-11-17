/**
 * Contracts 0.2.6 conformance proofs for @browsercore/tls.
 *
 * 1. TlsHandshakeEngine (src/tls-engine.ts): type-level check that tls
 *    SATISFIES the contracts `TlsHandshakeEngine` interface today — the proof
 *    backing quic's engine injection next batch (replaceability audit
 *    2026-11-16, remediation item #2: quic must stop importing
 *    @browsercore/tls directly and receive the engine via options; tls is
 *    formally "an implementation of the contracts handshake engine").
 *
 *    The three functions are wired from the PUBLIC barrel (`src/index.ts`) —
 *    the exact surface a composition root would hand to quic. If any
 *    signature or wire type drifts away from the contract, THIS FILE fails to
 *    compile: `const engine: TlsHandshakeEngine = { ... }` is the whole proof.
 *
 * 2. Clock (src/time.ts): runtime check that the migrated `systemClock`
 *    (0.4.17) implements the FULL canonical Clock — not just the now/sleep
 *    subset tls calls today.
 *
 * Compile proof: this file is typechecked by `npm run typecheck` via
 * tsconfig.test.json (the dual src+tests gate — tests used to sit outside the
 * gate, which left this proof unvalidated; see that config's header). Both
 * directions are enforced on every CI run:
 *   - the positive wiring below must compile against the contract;
 *   - the @ts-expect-error negative control must suppress a REAL error — if
 *     the constraint ever loosens, tsc flags the unused directive (TS2578)
 *     and the gate fails instead of silently going vacuous.
 */

import { describe, expect, it } from "vitest";
import type { Clock, TlsHandshakeEngine } from "@browsercore/contracts";
import { cipherSuiteToAead, generateKeyShares, runHandshake, systemClock } from "../src/index.js";

// ===========================================================================
// THE PROOF — tls's real functions, structurally assigned to the contract
// ===========================================================================

const engine: TlsHandshakeEngine = {
    runHandshake,
    generateKeyShares,
    cipherSuiteToAead,
};

// Negative control — proves the assignment above is a live constraint, not a
// vacuous `any`-shaped hole: a shape that is NOT the engine must not compile.
// @ts-expect-error — missing generateKeyShares, cipherSuiteToAead takes the wrong type
const notAnEngine: TlsHandshakeEngine = { runHandshake, cipherSuiteToAead: (n: number) => n };

// ===========================================================================
// Runtime smoke — the engine object delegates to the real functions
// ===========================================================================

describe("TlsHandshakeEngine conformance (contracts 0.2.6)", () => {
    it("wires tls's runHandshake / generateKeyShares / cipherSuiteToAead onto the contract", () => {
        expect(typeof engine.runHandshake).toBe("function");
        expect(typeof engine.generateKeyShares).toBe("function");
        expect(typeof engine.cipherSuiteToAead).toBe("function");
        // The negative control exists only to fail compilation; keep it referenced
        // so noUnusedLocals stays satisfied.
        expect(notAnEngine).toBeDefined();
    });

    it("maps every negotiable TLS 1.3 suite to its AEAD through the engine object", () => {
        expect(engine.cipherSuiteToAead("TLS_AES_128_GCM_SHA256")).toBe("AES-128-GCM");
        expect(engine.cipherSuiteToAead("TLS_AES_256_GCM_SHA384")).toBe("AES-256-GCM");
        expect(engine.cipherSuiteToAead("TLS_CHACHA20_POLY1305_SHA256")).toBe("CHACHA20-POLY1305");
        expect(engine.cipherSuiteToAead("TLS_AES_128_CCM_SHA256")).toBe("AES-128-CCM");
    });
});

// ===========================================================================
// Canonical Clock conformance — the migrated systemClock (0.4.17) implements
// the FULL contracts Clock, not just the now/sleep subset tls calls today.
// ===========================================================================

describe("canonical Clock conformance (contracts 0.2.6)", () => {
    it("systemClock satisfies the full contracts Clock surface", () => {
        const clock: Clock = systemClock;
        expect(typeof clock.now).toBe("function");
        expect(typeof clock.monotonic).toBe("function");
        expect(typeof clock.sleep).toBe("function");
        expect(typeof clock.setTimeout).toBe("function");
        expect(typeof clock.clearTimeout).toBe("function");
    });

    it("now() is wall time and monotonic() advances with it", async () => {
        const beforeWall = Date.now();
        const beforeMono = systemClock.monotonic();
        await systemClock.sleep(5);
        expect(systemClock.now()).toBeGreaterThanOrEqual(beforeWall);
        expect(systemClock.monotonic()).toBeGreaterThan(beforeMono);
    });

    it("setTimeout fires and clearTimeout cancels via the opaque TimerHandle", async () => {
        let fired = false;
        const handle = systemClock.setTimeout(5, () => { fired = true; });
        systemClock.clearTimeout(handle);
        await systemClock.sleep(15);
        expect(fired).toBe(false);

        let firedLater = false;
        const liveHandle = systemClock.setTimeout(5, () => { firedLater = true; });
        expect(typeof liveHandle).toBe("object");
        await systemClock.sleep(20);
        expect(firedLater).toBe(true);
    });
});
